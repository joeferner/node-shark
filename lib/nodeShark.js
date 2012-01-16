

var bindings = require("../build/Release/nodeshark_bindings");

exports.LINK_LAYER_TYPE_ETHERNET = 1;

exports.Dissector = bindings.Dissector;
exports.TcpTracker = require("./tcpTracker");
exports.HttpTracker = require("./httpTracker");

exports.toObject = toObject = function(packet, parentNode, node, rawPacket) {
  var childPacket;
  if(node.root) {
    packet.dataSources = node.dataSources;
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
    else if(packet.jsonBuilder) {
      if(node.abbreviation == 'json.object') {
        if(packet.jsonCurrent instanceof Array) {
          var temp = packet.jsonCurrent;
          packet.jsonCurrent = {};
          node.childenForEach(packet, toObject);
          temp.push(packet.jsonCurrent);
          packet.jsonCurrent = temp;
        } else {
          if(!packet.jsonCurrent) {
            packet.jsonCurrent = {};
          }
          node.childenForEach(packet, toObject);
        }
      } else if(node.abbreviation == 'json.array') {
        var temp = packet.jsonCurrent;
        packet.jsonCurrent = [];
        node.childenForEach(packet, toObject);
      } else if(node.abbreviation == 'json.member') {
        var match = node.representation.match(/.*?: "(.*?)"/);
        var name = match[1];
        var temp = packet.jsonCurrent;
        packet.jsonCurrent = null;
        node.childenForEach(packet, toObject);
        temp[name] = packet.jsonCurrent;
        packet.jsonCurrent = temp;
      } else if(node.abbreviation.match(/json.value./)) {
        if(node.representation) {
          packet.jsonCurrent = node.representation.split(':')[1].trim();
        } else {
          var val = node.value;
          if(val) {
            val = val.replace(/\\r/g, '\r').replace(/\\n/g, '\n');
          }
          packet.jsonCurrent = val;
        }
      } else {
        throw new Error("invalid JSON: " + node.abbreviation);
      }
      return;
    }
    else if(node.abbreviation == 'json') {
      childData = { jsonBuilder: true, jsonData: {} };
      childData.jsonCurrent = childData.jsonData;
      node.childenForEach(childData, toObject);
      packet['data-text-lines'] = JSON.stringify(childData.jsonData);
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
    return this._dissect(data);
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

exports.getRawValue = function(packet, node) {
  var dataSource = packet.dataSources[node.dataSource];
  return dataSource.slice(node.positionInPacket, node.positionInPacket + node.sizeInPacket);
}

