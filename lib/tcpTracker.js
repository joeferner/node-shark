
var util = require("util");
var events = require("events");

module.exports = TcpTracker = function() {
  this.sessions = {};
  events.EventEmitter.call(this);
}
util.inherits(TcpTracker, events.EventEmitter);

TcpTracker.prototype.track = function(packet) {
  if(!packet || !packet.tcp || !packet.tcp.stream) {
    return;
  }
  var streamId = packet.tcp.stream.showValue;
  var session = this.sessions[streamId];
  if(!session) {
    session = {
      streamId: streamId,
      srcIp: packet.ip.src.showValue,
      srcPort: packet.tcp.srcport.showValue,
      dstIp: packet.ip.dst.showValue,
      dstPort: packet.tcp.dstport.showValue,
      packetCount: 0,
      isPacketFromDestination: function(packet) {
        if(packet.ip && packet.tcp
           && this.dstIp == packet.ip.src.showValue
           && this.dstPort == packet.tcp.srcport.showValue) {
          return true;
        }
        return false;
      }
    };
    this.sessions[streamId] = session;
    this.emit('start', session);
  }

  session.packetCount++;
  this.emit('packet', session, packet);

  // TODO: detect close
  // this.emit('end', session);
}
