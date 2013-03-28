import urllib2
import urllib
import socket
import xml.etree.ElementTree as ET
import re

class BlueSocket:
    _defultRedirect = 'http://www.google.co.uk/generate_204'
    
    def __init__(self):
        self.lastError = None
        self.loginUrl = None
    
    def getLoginUrl(self):
        if self.loginUrl == None:
            redirectUrl = BlueSocket._defultRedirect
            req = urllib2.Request(redirectUrl)
            res = urllib2.urlopen(req)
            newUrl = res.geturl()
            if newUrl != redirectUrl:
                self.loginUrl = newUrl.split('?')[0]
        
        return self.loginUrl

    def isLoggedIn(self):
        return urllib2.urlopen(urllib2.Request(BlueSocket._defultRedirect)).geturl() == BlueSocket._defultRedirect

    def login(self, loginUrl, username, password):
        ip = socket.gethostbyname(socket.gethostname())
        packet = urllib.urlencode(
        {'_FORM_SUBMIT':1, 
         'which_form': 'reg', 
         'destination': '',
         'error':'', 
         'source': ip, 
         'SUBMIT': 'Log In', 
         'bs_name': username, 
         'bs_password': password})
        res = urllib2.urlopen(loginUrl, packet)

        responseText = res.read()
        self.lastError = self.parseResponseForError(responseText)

        return self.lastError == None

    def getLogoutUrl(self, loginUrl):
        url = loginUrl + '?action=logoutPopup'
        res = urllib2.urlopen(url)
        resText = res.read()
        regex = "'/login.pl(\?action=logout;[^']*)'"
        url = re.search(regex, resText)
        if url != None:
            return loginUrl + url.group(1)
        
        return None

    def logout(self, loginUrl):
        url = self.getLogoutUrl(loginUrl)
        if url != None:
            urllib2.urlopen(self.getLogoutUrl(loginUrl))
            #res = urllib2.urlopen(self.getLogoutUrl(loginUrl))
            #resText = res.read()
            return True
        
        return False

    def parseResponseForError(self, htmlPage, formName='bluesocket_u'):
        #This is all very hacky and fragile, but I didn't want to rely on
        #a third party library, and didn't want to do a big HTMLParser override class
        try:
            regex = '<form[^>]*>.*?</form>'
            msg = None
            forms = re.findall(regex, htmlPage, re.DOTALL)
            for form in forms:
                form = re.sub('&[^;]+;', ' ', form)
                f = ET.fromstring(form)
                if f.attrib.has_key('name') and f.attrib['name'] == formName:
                    error = f.find('input[@name="error"]')
                    msg = error.attrib['value']
                    if msg == '':
                        msg = None
                    break
    
            return msg
        except Exception as ex:
            return 'Unable to parse response: ' + str(ex.msg)
                    
    
    def getLastError(self):
        return self.lastError

def parseOptions():
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-u", "--username", dest="username",
                      help="BlueAccess username")
    parser.add_option("-p", "--password", dest="password", 
                  help="BlueAccess password")
    parser.add_option("-l", "--loginpage", dest="loginUrl", 
                  help="BlueAccess Login page (Use if haiving problems with autodetect)")
    parser.add_option("-s", "--status", dest="status", 
                  help="Display current login status.")
    parser.add_option("-o", "--logout",
                  action="store_false", dest="logout", default=False,
                  help="Log out of BlueAccess, -l required")
    
    (options, _) = parser.parse_args()
    if options.logout:
        if options.loginUrl == None:
            parser.error('LoginUrl required with logout option.')
        else:
            return options
    elif options.status:
        return options
    elif(options.username != None and options.password != None):
        return options
    else:
        parser.error('Username and password required for login.  Use --help for options.')

if __name__ == '__main__':
    
    options = parseOptions()
    b = BlueSocket()

    if options.logout:
        print 'Logging out..'
        if b.logout(options.loginUrl):
            print 'Logged out.'
        else:
            print 'Unable to log out.'
    else:
        print 'Checking current status...'
        if b.isLoggedIn():
            print '   Already logged in.'
        else:
            print '   Not logged in.'
        
            if not options.status:
                if options.loginUrl == None:
                    print 'Login URL not provided, autodetecting...'
                    options.loginUrl = b.getLoginUrl()
                    print 'Detected Login URL %s' % options.loginUrl
        
                print 'Logging into %s with user %s and password %s' % (
                                                        options.loginUrl,
                                                        options.username,
                                                        options.password)
        
                if b.login(options.loginUrl, options.username, options.password):
                    print 'Login Successful!'
                    print 'Logout URL: %s' % b.getLogoutUrl(options.loginUrl)
                else:
                    print 'Login Failed: ' + b.getLastError()