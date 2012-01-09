

var bindings = require("../build/Release/nodeshark_bindings");

exports.LINK_LAYER_TYPE_ETHERNET = 1;

exports.Dissector = bindings.Dissector;
exports.TcpTracker = require("./tcpTracker");
exports.HttpTracker = require("./httpTracker");

exports.toObject = toObject = function(packet, parentNode, node, rawPacket) {
  var childPacket;
  if(node.root) {
    packet.rawPacket = rawPacket;
    node.childenForEach(packet, toObject);
  } else {
    //console.log("node", packet, parentNode.abbreviation, node, rawPacket);
    var childData = {
      value: node.value
    };
    if(parentNode.abbreviation == 'data-text-lines') {
      packet.text += node.representation;
      return;
    }
    else if(node.abbreviation == 'data-text-lines') {
      childData = { text: "" };
      node.childenForEach(childData, toObject);
      packet['data-text-lines'] = childData.text;
      return;
    }
    else if(packet.xmlBuilder) {
      if(node.representation) {
        packet.text += node.representation + " ";
      }
      node.childenForEach(packet, toObject);
      return;
    }
    else if(node.abbreviation == 'xml') {
      childData = { xmlBuilder: true, text: "" };
      node.childenForEach(childData, toObject);
      packet['data-text-lines'] = childData.text;
      return;
    }
    else if(node.abbreviation == 'text') {
      if(node.representation) {
        packet[node.representation] = childData;
      }
    } else {
      var abbreviation = node.abbreviation;
      if(parentNode.abbreviation && abbreviation.match("^" + parentNode.abbreviation) == parentNode.abbreviation) {
        abbreviation = abbreviation.substr(parentNode.abbreviation.length + 1);
      }
      packet[abbreviation] = childData;
    }
    node.childenForEach(childData, toObject);
  }
}

exports.Dissector.prototype.dissect = function() {
  if(arguments.length == 1) {
    var data = arguments[0];
    var result = {};
    this._dissect(data, result, toObject);
    return result;
  } else if(arguments.length == 2) {
    var data = arguments[0];
    var callback = arguments[1];
    var result = {};
    this._dissect(data, {}, callback);
    return result;
  } else if(arguments.length == 3) {
    var data = arguments[0];
    var result = arguments[1];
    var callback = arguments[2];
    this._dissect(data, result, callback);
    return result;
  } else {
    throw new Error("Invalid number of arguments");
  }
}

exports.isStandardKey = function(key) {
  if(key == "sizeInPacket") return true;
  if(key == "posInPacket") return true;
  if(key == "showValue") return true;
  if(key == "value") return true;
  return false;
}