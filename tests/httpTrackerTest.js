

var nodeunit = require("nodeunit");
var nodeshark = require("../");
var util = require('util');
var pcapp = require('pcap-parser');

exports['HttpTrackerTest'] = nodeunit.testCase({
  "ethereal.com": function(test) {
    var dissector;

    var files = {};
    var tcpTracker = new nodeshark.TcpTracker();
    var httpTracker = new nodeshark.HttpTracker(tcpTracker);
    httpTracker.on("requestHeaders", function(http) {
      test.ok(http.request.fullUri);
      files[http.request.fullUri] = true;
    });
    httpTracker.on("requestData", function(http, buffer) {
      console.log("requestData --- ", buffer);
      test.ok(buffer);
    });
    httpTracker.on("responseHeaders", function(http) {
      test.ok(http.response.code, 200);
      files[http.request.fullUri] = true;
    });
    httpTracker.on("responseData", function(http, buffer) {
      files[http.request.fullUri] = buffer;
      test.ok(buffer);
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

      test.ok(files["http://www.ethereal.com/"]);
      test.equal(files["http://www.ethereal.com/"].length, 4609);

      test.ok(files["http://www.ethereal.com/mm/css/ethereal-3-0.css"]);
      test.equal(files["http://www.ethereal.com/mm/css/ethereal-3-0.css"].length, 4609);

      test.ok(files["http://www.ethereal.com/mm/image/elogo-64-trans.gif"]);
      test.equal(files["http://www.ethereal.com/mm/image/elogo-64-trans.gif"].length, 4609);

      test.ok(files["http://www.ethereal.com/mm/image/go-button.gif"]);
      test.equal(files["http://www.ethereal.com/mm/image/go-button.gif"].length, 4609);

      test.ok(files["http://pagead2.googlesyndication.com/pagead/show_ads.js"]);
      test.equal(files["http://pagead2.googlesyndication.com/pagead/show_ads.js"].length, 8020);

      test.ok(files["http://www.ethereal.com/mm/image/NISlogo75.gif"]);
      test.equal(files["http://www.ethereal.com/mm/image/NISlogo75.gif"].length, 4609);

      test.ok(files["http://www.ethereal.com/mm/image/front-wind.png"]);
      test.equal(files["http://www.ethereal.com/mm/image/front-wind.png"].length, 4609);

      test.ok(files["http://pagead2.googlesyndication.com/pagead/ads?client=ca-pub-2309191948673629&dt=1099056744465&lmt=1098371814&format=120x600_as&output=html&url=http%3A%2F%2Fwww.ethereal.com%2F&color_bg=FFFFFF&color_text=333333&color_link=000000&color_url=666633&color_border=666633&u_h=768&u_w=1024&u_ah=738&u_aw=1024&u_cd=32&u_tz=-240&u_his=3&u_java=true&u_nplug=14&u_nmime=49"]);
      test.equal(files["http://pagead2.googlesyndication.com/pagead/ads?client=ca-pub-2309191948673629&dt=1099056744465&lmt=1098371814&format=120x600_as&output=html&url=http%3A%2F%2Fwww.ethereal.com%2F&color_bg=FFFFFF&color_text=333333&color_link=000000&color_url=666633&color_border=666633&u_h=768&u_w=1024&u_ah=738&u_aw=1024&u_cd=32&u_tz=-240&u_his=3&u_java=true&u_nplug=14&u_nmime=49"].length, 4609);

      test.ok(files["http://www.ethereal.com/favicon.ico"]);
      test.equal(files["http://www.ethereal.com/favicon.ico"].length, 4609);

      test.done();
    });

    pcapParser.parse();
  }
});
