
import struct
import sys
from zope.interface import implements
from twisted.internet.protocol import Protocol
from twisted.conch.openssh_compat.primes import parseModuliFile
from twisted.conch.checkers import SSHPublicKeyChecker, InMemorySSHKeyDB
from twisted.conch.ssh.factory import SSHFactory
from twisted.conch.ssh.transport import SSHServerTransport
from twisted.cred import portal
from twisted.conch import avatar
from twisted.conch.ssh import connection, session, keys, userauth
from twisted.conch.ssh.session import SSHSessionProcessProtocol, wrapProtocol
from twisted.internet import reactor
from twisted.python import log
from twisted.conch.ssh.common import getNS
log.startLogging(sys.stderr)

class DeveloperAvatar(avatar.ConchUser):
    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.channelLookup.update({
            'session': MainSession
        })

class MetisRealm(object):
    implements(portal.IRealm)

    def requestAvatar(self, avatarId, mind, *interfaces):
        return interfaces[0], DeveloperAvatar(avatarId), lambda: None

class MetisSSHFactory(SSHFactory):

    def __init__(self, portal):
        self.services = {
            'ssh-userauth': userauth.SSHUserAuthServer,
            'ssh-connection': connection.SSHConnection
        }
        self.publicKeys = {
            'ssh-rsa': keys.Key.fromFile('host_keys/host_rsa.pub')
        }
        self.privateKeys = {
            'ssh-rsa': keys.Key.fromFile('host_keys/host_rsa')
        }
        self.protocol = SSHServerTransport
        self.primes = parseModuliFile('/etc/moduli')
        self.portal = portal

class EchoProtocol(Protocol):

    def dataReceived(self, data):
        if data == '\r':
            data = '\r\n'
        elif data == '\x03': #^C
            self.transport.loseConnection()
            return
        self.transport.write(data)

class MainSession(session.SSHSession):
    name = 'session'

    def __init__(self, *args, **kw):
        session.SSHSession.__init__(*args, **kw) #old style class
        self.env = {}

    def request_pty_req(self, data):
        print "request pty"
        return True

    def request_shell(self, data):
        protocol = EchoProtocol()
        transport = SSHSessionProcessProtocol(self)
        protocol.makeConnection(transport)
        transport.makeConnection(wrapProtocol(protocol))
        self.client = transport
        return True

    def request_env(self, data):
        (key, value, _) = getNS(data, count=2)
        self.env[key] = value
        return True

if __name__ == '__main__':
    portal = portal.Portal(MetisRealm())
    sshDB = SSHPublicKeyChecker(InMemorySSHKeyDB({'edd': [keys.Key.fromFile('/Users/edd/.ssh/id_rsa.personal.pub')]}))
    portal.registerChecker(sshDB)
    factory = MetisSSHFactory(portal)
    reactor.listenTCP(5022, factory)
    reactor.run()
