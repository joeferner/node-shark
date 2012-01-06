

var nodeunit = require("nodeunit");
var nodeshark = require("../");
var util = require('util');
var pcapp = require('pcap-parser');

exports['HttpTrackerTest'] = nodeunit.testCase({
  "ethereal.com": function(test) {
    var dissector;

    var tcpTracker = new nodeshark.TcpTracker();
    var httpTracker = new nodeshark.HttpTracker(tcpTracker);
    httpTracker.on("requestHeaders", function(http) {
      test.ok(http.request.fullUri);
    });
    httpTracker.on("responseHeaders", function(http) {
      test.ok(http.response.code, 200);
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
