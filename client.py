
"""
Metis command line client

Usage:
    client.py <HOST> [-p <PORT>] [-i <KEY>]

Options:
    -p <PORT> --port=<PORT>    change the port to connect to [default: 5022].
    -i <KEY>  --key=<KEY>      the private key to authenticate with.
"""

from twisted.internet.endpoints import UNIXClientEndpoint
from twisted.internet.protocol import Factory
from twisted.internet import protocol, reactor
from twisted.conch.ssh.userauth import SSHUserAuthClient
from twisted.conch.ssh.keys import Key
from twisted.conch.client.agent import SSHAgentClient
from twisted.conch.client.knownhosts import KnownHostsFile, ConsoleUI
from twisted.conch import error
from twisted.conch.ssh import transport
from twisted.conch.ssh import connection
from twisted.conch.ssh import channel, common
from twisted.internet.defer import Deferred, succeed, CancelledError, failure
from twisted.python.filepath import FilePath
from twisted.python import log
from twisted.python.failure import Failure
import os
import sys
import inspect
from docopt import docopt

log.startLogging(sys.stdout, setStdout=0)

class AuthenticationFailed(Exception):

    def __init__(self):
        super(AuthenticationFailed, self).__init__(
            "An SSH session could not be established because authentication was not successful."
        )

class UserAuth(SSHUserAuthClient):
    keys = None
    agent = None

    def getPublicKey(self):
        if self.agent is not None:
            return self.agent.getPublicKey()

        if self.keys:
            self.key = self.keys.pop(0)
        else:
            self.key = None
        return self.key.public()

    def signData(self, publicKey, signData):
        if self.agent is not None:
            return self.agent.signData(publicKey.blob(), signData)
        else:
            return SSHUserAuthClient.signData(self, publicKey, signData)

    def getPrivateKey(self):
        return succeed(self.key)

    def connectToAgent(self, endpoint):
        factory = Factory()
        factory.protocol = SSHAgentClient
        d = endpoint.connect(factory)
        def connected(agent):
            self.agent = agent
            return agent.getPublicKeys()
        d.addCallback(connected)
        return d

    def serviceStopped(self):
        self.loseAgentConnection()

    def loseAgentConnection(self):
        if self.agent is None:
            return
        self.agent.transport.loseConnection()

class ClientTransport(transport.SSHClientTransport):

    # STARTING -> SECURING -> AUTHENTICATING -> CHANNELLING -> RUNNING
    def __init__(self, factory):
        self.factory = factory
        self._state = b'STARTING'
        self.knownHosts = KnownHostsFile.fromPath(
            FilePath(os.path.expanduser('~/.ssh/known_hosts'))
        )
        self._hostKeyFailure = None
        self._user_auth = None
        self._connection_lost_reason = None

    def verifyHostKey(self, pubKey, fingerprint):
        self._state = b'SECURING'

        hostname = self.factory.hostname
        ip = self.transport.getPeer().host
        d = self.knownHosts.verifyHostKey(self.factory.ui, hostname, ip, Key.fromString(pubKey))
        d.addErrback(self._saveHostKeyFailure)
        return d

    def _saveHostKeyFailure(self, reason):
        self._hostKeyFailure = reason
        return reason

    def connectionSecure(self):
        self._state = b'AUTHENTICATING'

        def running_cb(_):
            self._state = b'RUNNING'

        cb = Deferred()
        cb.addCallback(running_cb)

        self._user_auth = UserAuth(os.getlogin(), ClientConnection(cb))

        if "SSH_AUTH_SOCK" in os.environ:
            agentEndpoint = UNIXClientEndpoint(reactor, os.environ["SSH_AUTH_SOCK"])
            d = self._user_auth.connectToAgent(agentEndpoint)
        else:
            d = succeed(None)

        def agent_init_done(_):
            self.requestService(self._user_auth)
        d.addBoth(agent_init_done)

    def ssh_USERAUTH_SUCCESS(self, packet):
        self.transport._state = b'CHANNELLING'
        return SSHUserAuthClient.ssh_USERAUTH_SUCCESS(self, packet)

    #override the transport's disconnect method to intercept reasons
    def sendDisconnect(self, reason, description):
        if reason == 14:
            self._connection_lost_reason = AuthenticationFailed()
        transport.SSHClientTransport.sendDisconnect(self, reason, description)

    def connectionLost(self, reason):
        if self._connection_lost_reason is not None:
            #we've already determined the reason
            return
        if self._state == b'SECURING' and self._hostKeyFailure is not None:
            reason = self._hostKeyFailure
        elif self._state == b'AUTHENTICATING':
            self._connection_lost_reason = AuthenticationFailed()

class ClientConnection(connection.SSHConnection):

    def __init__(self, ready_cb):
        connection.SSHConnection.__init__(self)
        self.ready_cb = ready_cb

    def serviceStarted(self):
        self.openChannel(MainChannel(conn = self))
        self.ready_cb.callback(None)

class MainChannel(channel.SSHChannel):

    name = 'session'

    def channelOpen(self, data):
        d = self.conn.sendRequest(self, 'shell', '', wantReply = 1)
        d.addCallback(self._cb_shell_open)
        self.echoData = ''

    def _cb_shell_open(self, ignored):
        self.write('sup dawg')
        self.conn.sendEOF(self)
        self.loseConnection()

    def dataReceived(self, data):
        self.echoData += data

    def closed(self):
        print 'We got this back:', self.echoData
        reactor.stop()

class SSHClientFactory(protocol.ClientFactory):

    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.ui = ConsoleUI(lambda : open("/dev/tty", "r+b"))

    def buildProtocol(self, addr):
        self.client = ClientTransport(self)
        return self.client

    def clientConnectionLost(self, connector, reason):
        if self.client._connection_lost_reason is not None:
            print str(self.client._connection_lost_reason)
        self.client = None
        reactor.stop()

    def clientConnectionFailed(self, connector, reason):
        print "CONNECTION FAILED"
        print reason

def main():
    args = docopt(__doc__)
    host = args.get('<HOST>')
    port = args.get('--port')
    factory = SSHClientFactory(host, port)
    reactor.connectTCP(host, int(port), factory)
    reactor.run()

if __name__ == "__main__":
    main()

