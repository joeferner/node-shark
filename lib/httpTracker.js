
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
  if(!httpTrackerSession && !packet.http) {
    return;
  }

  // request
  if(!httpTrackerSession || (packet.http && packet.http.request && packet.http.request.showValue == 1)) {
    httpTrackerSession = {
      state: 'REQUEST',
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
    this.emit("requestHeaders", httpTrackerSession);
  }

  // response
  else if(packet.http && packet.http.response && packet.http.response.showValue == 1) {
    httpTrackerSession.state = 'RESPONSE';
    this._populateRequestOrResponse(httpTrackerSession.response, packet);
    this.emit("responseHeaders", httpTrackerSession);
  }
}

HttpTracker.prototype._populateRequestOrResponse = function(requestResponse, packet) {
  for(var key in packet.http) {
    if(nodeshark.isStandardKey(key)) continue;
    if(key == '\\r\\n') continue;
    if(key == 'request') continue;
    if(key == 'response') continue;
    if(key == 'request.full_uri') {
      requestResponse.fullUri = packet.http[key].showValue;
      continue;
    }
    if(packet.http[key]["http.request.method"]) {
      requestResponse.method = packet.http[key]["http.request.method"].showValue;
      requestResponse.uri = packet.http[key]["http.request.uri"].showValue;
      requestResponse.version = packet.http[key]["http.request.version"].showValue;
      continue;
    }
    if(packet.http[key]["http.response.code"]) {
      requestResponse.codeString = packet.http[key]["http.response.phrase"].showValue;
      requestResponse.code = packet.http[key]["http.response.code"].showValue;
      requestResponse.version = packet.http[key]["http.request.version"].showValue;
      continue;
    }
    if(key.match(/\\r\\n$/) == "\\r\\n") {
      var shortKey = key.slice(0, key.length-4);
      var token = shortKey.indexOf(':');
      if(token > 0) {
        var name = shortKey.slice(0, token);
        var value = shortKey.slice(token+2);
        requestResponse.headers[name] = value;
        continue;
      }
    }
    requestResponse.headers[this._headerKeyToDisplay(key)] = packet.http[key].showValue;
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
  return key;
}
