

var nodeunit = require("nodeunit");
var nodeshark = require("../");

exports['NodeSharkTest'] = nodeunit.testCase({
  "process packet": function(test) {
    nodeshark.doit();
    test.done();
  }
});
