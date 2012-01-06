

var nodeunit = require("nodeunit");
var nodeshark = require("../");
var util = require('util');
var pcapp = require('pcap-parser');

exports['TcpTrackerTest'] = nodeunit.testCase({
  "ethereal.com": function(test) {
    var dissector;

    var tcpTracker = new nodeshark.TcpTracker();
    tcpTracker.on('start', function(session) {
      //console.log("start", session);
    });
    tcpTracker.on('packet', function(session, packet) {
      //console.log("packet", session);
    });
    tcpTracker.on('end', function(session) {
      //console.log("end", session);
    });

    var pcapParser = new pcapp.Parser('./test_data/ethereal.com.pcap');
    pcapParser.on('globalHeader', function(globalHeader) {
      dissector = new nodeshark.Dissector(globalHeader.linkLayerType);
    });
    pcapParser.on('packet', function(rawPacket) {
      var packet = dissector.dissect(rawPacket);
      tcpTracker.track(packet);
    });
    pcapParser.on('end', function() {
      test.equal(tcpTracker.sessions[0].packetCount, 30);
      test.equal(tcpTracker.sessions[1].packetCount, 35);
      test.equal(tcpTracker.sessions[2].packetCount, 15);
      test.done();
    });
    
    pcapParser.parse();
  }
});
