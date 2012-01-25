#!/usr/bin/env node

var optimist = require('optimist');
var nodeshark = require("../");
var pcapp = require("pcap-parser");

var argv = optimist
    .default({ verbose: false, infile: true })
    .usage('Usage: $0 [options]')
    .alias('infile', 'i')
    .alias('field', 'f')
    .alias('verbose', 'v')
    .alias('h', 'help')
    .alias('h', '?')
    .describe('infile', 'The file to read input from. Leave blank for stdin.')
    .describe('field', 'The field to print (ie request.fullUri).')
    .describe('verbose', 'Verbose mode.')
    .argv

var verbose = argv.verbose;

if (argv.help) {
  optimist.showHelp();
  process.exit(1);
}

if(!(argv.field instanceof Array)) {
  argv.field = [ argv.field ];
}

var pcapparser;
if (argv.infile === true) {
  if(verbose) console.error("Loading pcap file from stdin");
  pcapparser = new pcapp.Parser(process.stdin);
} else {
  if(verbose) console.error("Loading pcap file: " + argv.infile);
  pcapparser = new pcapp.Parser(argv.infile);
}

var dissector;
var tcpTracker = new nodeshark.TcpTracker();
var httpTracker = new nodeshark.HttpTracker(tcpTracker);

pcapparser.on('globalHeader', function(globalHeader) {
  dissector = new nodeshark.Dissector(globalHeader.linkLayerType);
});

pcapparser.on('packet', function (rawPacket) {
  var packet = dissector.dissect(rawPacket);
  evalFields(packet);
  tcpTracker.track(packet);
});

pcapparser.on('end', function() {
  dissector.close();
});

httpTracker.on('responseData', function (http, buffer) {
  //console.log(http);
  evalFields(http);
  for(var i=0; i<argv.field.length; i++) {
    var f = argv.field[i];
    if(f == 'responseData' && buffer) {
      console.log(buffer.toString());
    }
  }
});

pcapparser.parse();

function evalFields(p) {
  for(var i=0; i<argv.field.length; i++) {
    var f = argv.field[i];
    if(!f) continue;
    var str;
    if(f[0] == '[') {
      str = "p" + f;
    } else {
      str = "p." + f;
    }
    try {
      var r = eval(str);
      if(r) {
        console.log(f + ":", r);
      }
    } catch(e) {
      // ignore
    }
  }
}
