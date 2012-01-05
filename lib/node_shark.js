

var bindings = require("../build/Release/nodeshark_bindings");
var nodesharkBindings = new bindings.NodeShark();

exports.doit = function(settings, callback) {
  nodesharkBindings.doIt(settings, callback);
}
