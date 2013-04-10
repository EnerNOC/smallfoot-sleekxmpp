'''
Created on Sep 2, 2010

@author: bbeggs
'''
from . import base
import os
import random
import logging
import hashlib
from .. xmlstream.stanzabase import ElementBase, ET
from xml.etree.cElementTree import XML, tostring
from sleekxmpp.xmlstream.stanzabase import ElementBase
from sleekxmpp.xmlstream.handler.xmlcallback import XMLCallback
from sleekxmpp.xmlstream.matcher.xmlmask import MatchXMLMask
import time

PROTOCOL_SI_XMLNS            = 'http://jabber.org/protocol/si'
PROTOCOL_SI_PROFILE_FT_XMLNS = 'http://jabber.org/protocol/si/profile/file-transfer'
PROTOCOL_FEATURENEG_XMLNS    = 'http://jabber.org/protocol/feature-neg'

def generateSid():
    sid = ''
    for i in range(7):
        sid+=hex(int(random.random()*65536*4096))[2:]
    return sid[:8].upper()

class FileTransferProtocol(base.base_plugin):
    '''
    This is a base class that must be implemented by any xep that provides
    bytestream transfer for xepp.  Examples of this are XEP-0047 and XEP-0066.
    
    This class provides the minimum interfaces needed to support bytestreams
    in conjunction with xep-0096.  If an implementation of this interface should
    call it's super classes method if there is already an implementation provided.
    
    Interfaces that should be implemented:
        sendFile(self, fileName, to, threaded=True, sid=None):
            This is the method to send a file.  It should provided a blocking and
            a non-blocking option
            
        getSessionStatus(self, sid):
            This method should return a dict with the current status of the 
            bytestream for a given sid.  
            
            @return format:
            {'sid': string, 'processing' : boolean, 'otherPartyJID' : string,
             'streamClosed' : boolean, 'lastMessageTimestamp' : long, 
             'incFileName' <optional> : string, incFileKBytes <optional> : long,
             'outFileKbytes' <optional> : long}
             
        getSessionStatusAll(self):
            Should return a list of getSessionStatus for all bytestreams currently
            being transfered by the plugin.
            
        cancelSend(self, sid):
            Should cancel the bytestream for a given sid.  Once the stream has
            been terminated and everything cleaned up, xep_0096 should be notified
            that the transfer has ended by calling either fileFinishedReceiving 
            or fileFinishedSending
            
        
    The following methods already have an implementation provided.  If a protocol
    implementation needs to override any of these methods, the overriding method 
    must call the super implmentation.
    
        post_init(self):
            Provides registration with xep_0096 to add the bytestream protocol 
            as an available feature for file transfer
            
        fileFinishedReceiving(self, sid, filename):
            fires the an event that signals that a file has finished sending. The
            fired event comes with a dict that contains the sid of the bytestream
            as well as the filename.
    
        fileFinishedSending(self, sid, success):
            fires an event that signals that a file has finished receiving.  The
            fired event comes with a dict that contains the sid of the bytestream
            and a boolean value containing the success of the transfer
        
    There are also 2 events that users of this plugin can register to receive notifications:
    FILE_FINISHED_SENDING     - This event is fired after a file send has completed
    FILE_FINISHED_RECEIVING   - This event is fired after an incoming file transfer has completed.
    
    !!!!!!!!!!!When registering to receive notifications about these events the
    callback functions should be registered as threaded!!!!!!!!!
    '''
    
    FILE_FINISHED_SENDING = 'BYTE_STREAM_SENDING_COMPLETE'
    FILE_FINISHED_RECEIVING = 'BYTE_STREAM_RECEIVING_COMPLETE'
    
    XMLNS = '' #MUST be overwritten by the implementer to be the namespace for
               #the implementing protocol
    
    def post_init(self):
        '''
        If xep_0096 is loaded it MUST be used for bytestream transfer.  If
        xep_0096 is present in the system all callbacks and events will default
        to there, overwriting anything that may have been passed in during plugin
        config.
        
        If you want to use a bytestream protocol stand alone do not load xep_0096
        '''
        self.post_inited = True
        #Register feature with xep_0096
        if self.xmpp.plugin.get('xep_0096'):
            self.xmpp.plugin['xep_0096'].add_feature(self.XMLNS, self)
            self.acceptTransferCallback = self.xmpp.plugin['xep_0096'].protocolGetAcceptTransferRequest 
            self.fileNameCallback = self.xmpp.plugin['xep_0096'].protocolGetFilename
    
    def sendFile(self, fileName, to, threaded=True, sid=None, **kwargs):
        pass
    
    def getSessionStatus(self, sid):
        pass
    
    def getSessionStatusAll(self):
        pass
    
    def cancelSend(self, sid): 
        pass
    
    def fileFinishedReceiving(self, sid, filename, desc = None):
        dict = {'sid': sid, 'filename':filename}
        if desc is not None:
            dict['desc'] = desc
        self.xmpp.event(FileTransferProtocol.FILE_FINISHED_RECEIVING, dict)
    
    def fileFinishedSending(self, sid, success):
        self.xmpp.event(FileTransferProtocol.FILE_FINISHED_SENDING, {'sid': sid, 'success':success})        
    
    
class xep_0096(base.base_plugin):
    '''
    Implements initiation for bytestreams for xmpp.
    
    This plugin is to be used in conjuction with the actual protocols for 
    bytestreams such as XEP-0066 OR XEP-0047.  This plugin does not actually
    implement a bytestream transfer protocol, just the ability to set one up. 
    
    Any implementing protocols that wish to interface with SI (stream initiation)
    must implement the interface FileTransferProtocol.
    
    Plugin configuration options:
    preferredProtocolNS    - String      - The preferred file transfer protocol NS (ie for XEP-0047: http://jabber.org/protocol/ibb)
    acceptTransfers        - Boolean     - Sets the plugin to either accept or deny transfers
    saveDirectory          - String      - The default directory that incoming file transfers will be saved in
    saveNamePrefix         - String      - Prefix that will be prepended to the saved file name of an incoming transfer
    overwriteFile          - Boolean     - If an incoming file transfer should overwrite a file if that file already exists
    stanzaType             - String      - Either IQ or message,  Currently only iq is supported
    maxSessions            - integer     - The max number of send/receive sessions that may run concurrently
    acceptTransferCallback - Function ptr- This should be a function pointer that will return a boolean value letting the caller know if a 
                                           file transfer should or should not be accepted. The callback method will be passed the SI xml 
                                           the requestor sent to negotiate the stream.
    fileNameCallback       - function ptr- This should be a function pointer that will return a string with the full path and name a file should be saved as.  
                                           If the provided function pointer returns None or is not provided the default saveDirectory + saveNamePrefix_sid will be used.
                                           The callback method will be passed the SI xml the requestor sent to negotiate the stream.
    closeTransferCallback  - function ptr- This should be a function pointer that does not need to return anything.  This is used to notify
                                           an interested party that a file transfer has completed.  The callback function should take 1 argument
                                           that is a dict of information about the file transfer.  For more infomation on what is in this dictionay
                                           see the doc for xep_0096.parseRequestXMLToDict
    '''
    def plugin_init(self):
        self.xep = '0096'
        self.description = 'SI File Transfer'
        
        self.bytestreamProtocols = {}
        self.activeBytestreams = {}
        self.preferredProtocolNS = self.config.get('preferredProtocolNS')
        
        self.acceptTransfers = True
        self.saveDirectory = self.config.get('saveDirectory', '/tmp/')
        self.saveNamePrefix = self.config.get('saveNamePrefix', 'xep_0096_')        
        self.overwriteFile = self.config.get('overwriteFile', True)
        self.stanzaType = self.config.get('stanzaType', 'iq') #Currently only IQ is supported
        self.maxSessions = self.config.get('maxSessions', 2)
        
        #callbacks
        self.acceptTransferCallback = self.config.get('acceptTransferCallback')
        self.fileNameCallback = self.config.get('fileNameCallback')
        self.closeTransferCallback = self.config.get('closeTransferCallback')
        
        self.xmpp.registerHandler(XMLCallback('xep_0047_open_stream', 
                                              MatchXMLMask("<iq xmlns='%s' type='set'><si xmlns='%s'/></iq>" %(self.xmpp.default_ns, PROTOCOL_SI_XMLNS)),
                                              self._handleIncomingTransferRequest, 
                                              thread=True))
        self.xmpp.add_event_handler(FileTransferProtocol.FILE_FINISHED_RECEIVING, self._receiveCompleteHandler, True, False)
        self.xmpp.add_event_handler(FileTransferProtocol.FILE_FINISHED_SENDING, self._sendCompleteHandler, True, False)
      
    def post_init(self):
        if self.xmpp.plugin.get('xep_0030'):
            self.xmpp.plugin['xep_0030'].add_feature(PROTOCOL_SI_XMLNS)
            self.xmpp.plugin['xep_0030'].add_feature(PROTOCOL_SI_PROFILE_FT_XMLNS)
          
    def add_feature(self, namespace, protocol, rangeSupport = False):
        '''
        A bytestream protocol must implement FileTransferProtocol class.
        '''
        self.bytestreamProtocols[namespace] = {'protocol' : protocol, 'rangeSupport' : rangeSupport}
        
    def setPreferredProtocol(self, protocolNS):
        '''
        Set the preferred bytestream protocol.  Whenever a stream is attempted
        to start the plugin will always try to use this protocol first.
        
        protocolNS - string - the xml namespace of the preferred protocol
        '''
        if self.bytestreamProtocols.get(protocolNS):
            self.preferredProtocolNS = protocolNS
        else:
            raise Exception('Unknown protocol namespace: %s' %protocolNS)
        
    def acceptTransferRequest(self, xferInfo, xml):
        if self.acceptTransferCallback:
            return self.acceptTransferCallback(xml)
        else:
            return self.acceptTransfers
        
    def protocolGetAcceptTransferRequest(self, sid):
        '''
        Bytestream protocols implementing FileTransferProtocol should call this
        method to determine if a bytestream initiation request should be accepted
        '''
        if self.activeBytestreams.get(sid):
            return True
        else:
            return False
    
    def protocolGetFilename(self, sid):
        '''
        Bytestream protocols implementing FileTransferProtocol should call this
        method to get the filename for a newly opened bytestream.
        '''
        return self.activeBytestreams.get(sid)['filenameAndPath']
        
    
    def _handleIncomingTransferRequest(self, xml):
        '''
        Handles the negotiation of an incoming file transfer request.  
        
        '''
        logging.debug("incoming file transfer request: %s" %tostring(xml))
        
        xferInfo = parseRequestXMLToDict(xml)
        returnIQ = None
        
        #Check the current number of transfering going isn't more than allowed
        numTranfers = 0
        for protocol in self.bytestreamProtocols.values():
            numTranfers += len(protocol['protocol'].getSessionStatusAll())
        if numTranfers >= self.maxSessions:
            returnIQ = makeRejectStreamIQ(self.xmpp.makeIqError(xml.get('id')), xferInfo['otherParty'])
            
        #Check if the program is accepting transfers
        if self.acceptTransferRequest(xferInfo, xml) == False and returnIQ is None:
            logging.debug('rejecting transfer')
            returnIQ = makeRejectStreamIQ(self.xmpp.makeIqError(xml.get('id')), xml.get('to'))
        
        #check that the requested protocol is a feature available for use
        matchingProtocols = set(self.bytestreamProtocols.keys()).intersection(xferInfo['protocols'])
        if len(matchingProtocols) == 0 and returnIQ is None:
            returnIQ = makeNoValidStreamsIQ(self.xmpp.makeIqError(xml.get('id')), xml.get('to'))
         
            
        #None of the error conditions is true, we can accept the transfer
        if returnIQ is None:
            logging.debug('transfer accepted, for sid: %s' %xferInfo['sid'])
            #get the full filename and save path
            self.activeBytestreams[xferInfo['sid']] = xferInfo
            filenameAndPath = self.saveDirectory + self.saveNamePrefix + xferInfo['filename']
            if self.fileNameCallback:
                filenameAndPath = self.fileNameCallback(sid=xferInfo['sid'], xml=xml)
            xferInfo['filenameAndPath'] = filenameAndPath
            #Figure out which protocol to use
            #if there is no preferred protocol pop a matching 
            protocolNS = None
            if self.preferredProtocolNS and self.preferredProtocolNS in matchingProtocols:
                protocolNS = self.preferredProtocolNS
            else:  
                protocolNS = matchingProtocols.pop()
            xferInfo['selectedProtocol'] = self.bytestreamProtocols[protocolNS]['protocol']
            
            returnIQ = makeAcceptResultIQ(self.xmpp.makeIqResult(xml.get('id')), xml.get('from'), protocolNS)
                        
        returnIQ.send(block=False)   
        
    def _receiveCompleteHandler(self, dict):
        xferInfo = self.activeBytestreams.pop(dict['sid'])
        if 'desc' in dict:
            desc = dict['desc']
            xferInfo['desc'] = desc
        if self.closeTransferCallback:
            self.closeTransferCallback(xferInfo)
        
    def _sendCompleteHandler(self, dict):
        xferInfo = self.activeBytestreams.pop(dict['sid'])
        xferInfo['finished'] = True
        xferInfo['success'] = dict['success']
        if self.closeTransferCallback:
            self.closeTransferCallback(xferInfo)
    
    def sendFile(self, fileName, to, threaded=True, protocolNS=None, **kwargs):
        '''
        Sends a file to the intended receiver if the receiver is available and 
        willing to accept the transfer.  If the send is requested to be threaded 
        the session sid will be returned, otherwise the method will block until 
        the file has been sent and the session closed.
        
        The returned sid can be used to check on the status of the transfer or 
        cancel the transfer.
        
        If protocolNS is passed in a request for stream initiation will be sent 
        using only this protocol namespace (assuming that the protocol is registered 
        as a feature for this plugin)
        '''
        logging.debug('sending file...')
        #verify the file exists
        if not os.path.isfile(fileName):
            raise IOError('file: %s not found' %fileName)
        
        if protocolNS is not None and self.bytestreamProtocols.get(protocolNS) is None:
            raise Exception('''protocol %s is not a registered protocol with xep_0096\n
                            please use one of the following - %s''' %(protocolNS, self.bytestreamProtocols.keys()))
        
        
        sid = generateSid()
        md5 = hashlib.md5()
        with open(fileName) as f:
            while True:
                data = f.read(4096)
                if data == str(''): break
                md5.update(data)
        iq = makeStreamOfferIQ(self.xmpp.makeIqSet(), 
                               to, 
                               sid, 
                               self.bytestreamProtocols.keys() if protocolNS is None else protocolNS, 
                               fileName[fileName.rfind('/') + 1:], 
                               os.path.getsize(fileName),
                               fileHash=md5.hexdigest())
        result = iq.send(block=True, timeout=10)
        if result is False:
            logging.debug("Stream response timeout to %s, sid: %s", to, sid)
            raise Exception('Stream response timeout!')
        elif result.get('type') == 'error': 
            logging.debug('session rejected')
            raise Exception('Session rejected: %s' %result)
            '''
            if result.find('*/{urn:ietf:params:xml:ns:xmpp-stanzas}service-unavailable') != None:
                raise Exception('user not online! User: %s' %to)
            elif result.find('*/{urn:ietf:params:xml:ns:xmpp-stanzas}not-acceptable') != None:
                raise NotAcceptableException('Error setting up the stream, receiver not ready %s' %result)
            else:
                raise Exception('Unknown error! %s' %result)
            '''
            
        self.activeBytestreams[sid] = parseRequestXMLToDict(iq.xml)
        #get the negoiated protocol and send the file
        protocol = result.xml.findall('.//{jabber:x:data}x/{jabber:x:data}field/{jabber:x:data}value')[0].text
        self.activeBytestreams[sid]['selectedProtocol'] = self.bytestreamProtocols[protocol]['protocol']
        self.activeBytestreams[sid]['selectedProtocol'].sendFile(
                fileName, to, threaded=threaded, sid=sid, **kwargs)
        return sid
        
    def getSessionStatus(self, sid):
        '''
        returns the status of a bytestream for a given sid.
        '''
        return self.activeBytestreams[sid]['selectedProtocol'].getSessionStatus(sid)
        
    def getSessionStatusAll(self):
        '''
        returns the status for all currently active bytestreams
        '''
        sessions = {}
        for protocol in self.bytestreamProtocols.values():
            sessions.update(protocol['protocol'].getSessionStatusAll())
        return sessions
    
    def cancelSend(self, sid):
        '''
        Cancel a bytestream for a given sid
        '''
        self.activeBytestreams[sid]['selectedProtocol'].cancelSend(sid)
    
def parseRequestXMLToDict(xml):
    '''
    The xferInfo returned from this function may contain the following information:
        otherParty       - the full JID of the other party involved in the bytestream
        sid              - the unique id of the stream.
        filename         - name of file 
        filesize         - size in Kb of the file
        filehash         - the md5 sum of the file
        filedate         - the datestam on the file
        protocols        - a list of strings of bytestream protocols that may be used
        starttime        - timestamp of the time the request was made
        filenameAndPath  - the fully qualified path + name of the saved file
        selectedProtocol - the protocol that was selected to transfer the file.  This is a pointer to the actual implementation plugin object
        
    '''
    #Get the info on the request parse the inportant info in to a dict
    xferInfo = {}
    xferInfo['otherParty'] = xml.get('from')
    xferInfo['sid'] = xml.find('.//{http://jabber.org/protocol/si}si').get('id')
    elem = xml.find('.//{http://jabber.org/protocol/si}si/{http://jabber.org/protocol/si/profile/file-transfer}file')
    xferInfo['filename'] = elem.get('name').replace('/', '')
    xferInfo['filesize'] = elem.get('size')
    xferInfo['filehash'] = elem.get('hash')
    xferInfo['filedate'] = elem.get('date') 
    protocols = []
    items = xml.findall('.//{jabber:x:data}x/{jabber:x:data}field/{jabber:x:data}option/{jabber:x:data}value')
    for elem in xml.findall('.//{jabber:x:data}x/{jabber:x:data}field/{jabber:x:data}option/{jabber:x:data}value'):
        protocols.append(elem.text)
    xferInfo['protocols'] = protocols 
    xferInfo['startTime'] = time.time()
    xferInfo['endTime'] = None
    xferInfo['finished'] = False
    xferInfo['success'] = None
    return xferInfo 

def makeAcceptResultIQ(iq, to, protocol_ns):
    iq['to'] = to
    si = ET.Element('{%s}si' %PROTOCOL_SI_XMLNS)
    elem = ET.SubElement(si, '{%s}feature' %PROTOCOL_FEATURENEG_XMLNS)
    elem = ET.SubElement(elem, '{jabber:x:data}x', type='submit')
    elem = ET.SubElement(elem,'field', var='stream-method')
    elem = ET.SubElement(elem, 'value')
    elem.text = protocol_ns
    iq.setPayload(si)
    return iq
    
def makeRejectStreamIQ(iq, to):
    iq['to'] = to
    iq['type'] = 'error'
    return makeErrorIQ(iq, to, '403', 
                       '{urn:ietf:params:xml:ns:xmpp-stanzas}forbidden',
                       None, 
                       '{urn:ietf:params:xml:ns:xmpp-stanzas}text', 
                       'Offer Declined')
    
def makeNoValidStreamsIQ(iq, to):
    iq['to'] = to
    iq['type'] = 'error'
    return makeErrorIQ(iq, to, '400', 
                       '{urn:ietf:params:xml:ns:xmpp-stanzas}bad-request',
                       None, 
                       '{http://jabber.org/protocol/si}no-valid-streams', 
                       None)

def makeProfileNotUnderstoodIQ(iq, to):
    iq['to'] = to
    iq['type'] = 'error'
    return makeErrorIQ(iq, to, '400', 
                       '{urn:ietf:params:xml:ns:xmpp-stanzas}bad-request',
                       None, 
                       '{http://jabber.org/protocol/si}bad-profile', 
                       None)    


def makeErrorIQ(iq, to, errCode, elem0NS, elem0Txt=None, elem1NS=None, elem1Txt=None):
    iq['to'] = to
    error = ET.Element('error', code=str(errCode), type='cancel')
    for ns, txt in [(elem0NS, elem0Txt), (elem1NS, elem1Txt)]:
        if ns is not None:
            elem = ET.SubElement(error, ns)
            if txt is not None:
                elem.text = txt
    iq.setPayload(error)
    return iq

def makeStreamOfferIQ(iq, to, sid, protocolNS, fileName, fileSize=None, fileHash=None, fileDate=None, fileDesc=None):
    iq["to"] = to
    si = ET.Element('{%s}si' %PROTOCOL_SI_XMLNS, id=sid, profile=PROTOCOL_SI_PROFILE_FT_XMLNS)
    si.attrib['mime-type']='text/plain'
    elem = ET.SubElement(si, '{%s}file' %PROTOCOL_SI_PROFILE_FT_XMLNS)
    for k, v in [('name',fileName), ('size',str(fileSize)), ('hash',fileHash), ('date',fileDate)]:
        if v:
            elem.attrib[k] = v
    if fileDesc:
        desc = ET.SubElement(elem, 'desc')
        desc.text = fileDesc
    
    elem = ET.SubElement(si, '{%s}feature' %PROTOCOL_FEATURENEG_XMLNS)
    elem = ET.SubElement(elem, '{jabber:x:data}x', type='form')
    field = ET.SubElement(elem, '{jabber:x:data}field', var='stream-method', type='list-single')
    for protocol in protocolNS:
        elem = ET.SubElement(field, '{jabber:x:data}option')
        elem = ET.SubElement(elem, '{jabber:x:data}value')
        elem.text = protocol
    
    iq.setPayload(si)
    return iq
