

var bindings = require("../build/Release/nodeshark_bindings");

exports.LINK_LAYER_TYPE_ETHERNET = 1;

exports.Dissector = bindings.Dissector;
exports.TcpTracker = require("./tcpTracker");
exports.HttpTracker = require("./httpTracker");

exports.isStandardKey = function(key) {
  if(key == "sizeInPacket") return true;
  if(key == "posInPacket") return true;
  if(key == "showValue") return true;
  if(key == "value") return true;
  return false;
}