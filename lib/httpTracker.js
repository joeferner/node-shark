
var util = require("util");
var events = require("events");
var nodeshark = require('./nodeShark');

module.exports = HttpTracker = function(tcpTracker) {
  tcpTracker.on("packet", this._onPacket.bind(this));
  events.EventEmitter.call(this);
}
util.inherits(HttpTracker, events.EventEmitter);

HttpTracker.prototype._onPacket = function(session, packet) {
  var httpTrackerSession = session.httpTrackerSession;
  var self = this;

  if(!httpTrackerSession && !packet.http) {
    return;
  }

  // request
  if(packet.http && packet.http.request && packet.http.request.value == 1) {
    httpTrackerSession = {
      getTcpTrackerSession: function() { return session; },
      request: {
        headers: {

        }
      },
      response: {
        headers: {

        }
      }
    };
    session.httpTrackerSession = httpTrackerSession;

    this._populateRequestOrResponse(httpTrackerSession.request, packet);
    httpTrackerSession.request.getRawData = function() {
      return self._getRawData(packet);
    }
    this.emit("requestHeaders", httpTrackerSession);

    if(packet["data-text-lines"]) {
      this.emit("requestData", httpTrackerSession, packet["data-text-lines"]);
    }
  }

  // response
  if(httpTrackerSession && packet.http && packet.http.response && packet.http.response.value == 1) {
    this._populateRequestOrResponse(httpTrackerSession.response, packet);
    httpTrackerSession.response.getRawData = function() {
      return self._getRawData(packet);
    }
    this.emit("responseHeaders", httpTrackerSession);
    this.emit("responseData", httpTrackerSession);
  }
}

HttpTracker.prototype._getRawData = function(packet) {
  var data;
  if(packet["data-text-lines"]) {
    data = packet["data-text-lines"].rawData;
  } else if(packet["json"]) {
    data = packet["json"].rawData;
  } else if(packet["png"]) {
    data = packet["png"].rawData;
  } else if(packet["image-jfif"]) {
    data = packet["image-jfif"].rawData;
  } else if(packet["media"]) {
    data = packet["media"].rawData;
  } else if(packet["xml"]) {
    data = packet["xml"].rawData;
  } else if(packet["image-gif"]) {
    data = packet["image-gif"].rawData;
  } else {
    //console.log("could not find data: ", packet);
  }
  return data;
}

HttpTracker.prototype._populateRequestOrResponse = function(requestResponse, packet) {
  for(var key in packet.http) {
    if(nodeshark.isStandardKey(key)) continue;
    if(key == '\\r\\n') continue;
    if(key == 'request') continue;
    if(key == 'response') continue;
    if(key == 'request.full_uri') {
      requestResponse.fullUri = packet.http[key].value;
      continue;
    }
    if(packet.http[key]["http.request.method"]) {
      requestResponse.method = packet.http[key]["http.request.method"].value;
      requestResponse.uri = packet.http[key]["http.request.uri"].value;
      requestResponse.version = packet.http[key]["http.request.version"].value;
      continue;
    }
    if(packet.http[key]["http.response.code"]) {
      var phrase = packet.http[key]["http.response.phrase"];
      if(phrase) {
        requestResponse.codeString = phrase.value;
      }
      requestResponse.code = packet.http[key]["http.response.code"].value;
      requestResponse.version = packet.http[key]["http.request.version"].value;
      continue;
    }
    if(key.match(/\r\n$/) == "\r\n") {
      var shortKey = key.slice(0, key.length-2);
      var token = shortKey.indexOf(':');
      if(token > 0) {
        var name = shortKey.slice(0, token);
        var value = shortKey.slice(token+2);
        requestResponse.headers[name] = value;
        continue;
      }
    }
    requestResponse.headers[this._headerKeyToDisplay(key)] = packet.http[key].value;
  }
}


HttpTracker.prototype._headerKeyToDisplay = function(key) {
  if(key == 'host') return 'Host';
  if(key == 'user_agent') return 'User-Agent';
  if(key == 'accept') return 'Accept';
  if(key == 'accept_language') return 'Accept-Language';
  if(key == 'accept_encoding') return 'Accept-Encoding';
  if(key == 'connection') return 'Connection';
  if(key == 'referer') return 'Referer';
  if(key == 'date') return 'Date';
  if(key == 'server') return 'Server';
  if(key == 'last_modified') return 'Last-Modified';
  if(key == 'content_length_header') return 'Content-Length';
  if(key == 'content_type') return 'Content-Type';
  if(key == 'cache_control') return 'Cache-Control';
  if(key == 'set_cookie') return 'Set-Cookie';
  if(key == 'cookie') return 'Cookie';
  return key;
}
