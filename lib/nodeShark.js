

var bindings = tryRequire([
  "../build/Release/nodeshark_bindings",
  "../package/linux32/nodeshark_bindings"
]);

exports.LINK_LAYER_TYPE_ETHERNET = 1;

exports.Dissector = bindings.Dissector;
exports.TcpTracker = require("./tcpTracker");
exports.HttpTracker = require("./httpTracker");

exports.Dissector.prototype.dissect = function() {
  if(arguments.length == 1) {
    var data = arguments[0];
    return this._dissect(data);
  } else {
    throw new Error("Invalid number of arguments");
  }
}

exports.isStandardKey = function(key) {
  if(key == "sizeInPacket") return true;
  if(key == "positionInPacket") return true;
  if(key == "abbreviation") return true;
  if(key == "value") return true;
  if(key == "dataSource") return true;
  if(key == "rawData") return true;
  if(key == "text") return true;
  return false;
}

function tryRequire(array) {
  var firstError = null;
  for(var i=0; i<array.length; i++) {
    try {
      return require(array[i]);
    } catch(e) {
      if(!firstError) firstError = e;
    }
  }
  throw firstError;
}
