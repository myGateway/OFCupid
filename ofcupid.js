/**
 * Copyright (c) 2016 Richard Sanger
 *
 * Licensed under MIT
 */

var app = angular.module('patch_manager', []);

/** Angular filter to convert kbit/s to a human readable form */
app.filter('kbits', function() {
  return function(kbits) {
    if (kbits == 0) return "Down";
    var units = ['kb/s', 'Mb/s', 'Gb/s', 'Tb/s', 'Pb/s'];
    var magnitude = Math.floor(Math.log(kbits) / Math.log(1000));
    return (kbits / Math.pow(1000, Math.floor(magnitude))) + ' ' + units[magnitude];
  }
});

/** Angular filter to print a port in human readable form */
app.filter('print_port', function() {
    return function(port) {
        return port.port + " - " + port.port_name
    }
});

app.filter('print_vlan', function() {
    return function(port) {
        switch(port.vlan) {
            case -1:
                return "All including untagged"
                break;
            case 0:
                return "None"
                break;
            case 0xFFF:
                return "All"
                break;
            default:
                return port.vlan;
        }
    }
});

/** Global storage for logging errors so we can access from
 * our error controller and the logging provider */
errors = [];
/** Logging provider, warn and error messages are displayed to the
 * user */
app.config(["$provide", function($provide) {
  $provide.decorator("$log", function($delegate, logIntercept) {
    return logIntercept($delegate);
  });
}]);
app.factory("logIntercept", function() {
  return function($delegate) {
    return {
      log:function(){
        $delegate.log.apply(null, arguments);
      },
      info:function(){
        $delegate.info.apply(null, arguments);
      },
      error:function(){
        $delegate.error.apply(null, arguments);
        errors.push({'summary': arguments[0], 'msg': arguments[1],
          'type': 'error'});
      },
      warn:function(){
        $delegate.warn.apply(null, arguments);
        errors.push({'summary': arguments[0], 'msg': arguments[1],
          'type': 'warn'})
      },
      debug:function(){
        $delegate.debug.apply(null, arguments);
      }
    };
  };
});

/** Angular controller to pick the switch, the selected
 * switch is then used by all other controllers */
var pickSwitch = function ($scope, $http, $rootScope, $log) {
  $scope.select_switch = function() {
    $rootScope.dpid = $scope.userChoice;
    $rootScope.dpid_name = "";
    for (var i in $scope.switches) {
      var i = $scope.switches[i];
      if (i.dpid == $scope.userChoice) {
        $rootScope.dpid_name = i.dpid_name;
      }
    }
    $rootScope.$emit('refresh');
  };

  /** Handler for refresh button on nav menu - updates entire interface */
  $rootScope.$on('full_refresh', function(event, args) {
    $scope.refresh();
  });

  $scope.refresh = function() {
    $http.get('api/switches', {}).then(
      function(response) {
        $scope.switches = response.data;
        // This is buggy so we just zero it to match the UI
        $scope.userChoice = "";
        $scope.select_switch();
      },
      function(response) {
        $log.warn("Failed to load switches, are you sure the ryu server is running?", response.data);
      });
  };

  $rootScope.dpid = "";
  $rootScope.dpid_name = "";
  $scope.userChoice = "";
  $scope.refresh();
};

/** Angular controller for the ports tab. Fills the table and handles
 * logic of the buttons. */
var portsController = function ($scope, $http, $rootScope, $log) {

  $scope.refresh = function() {
    $http.post('api/ports', {'dpid': $rootScope.dpid}).then(
      function(response) {
        $scope.ports = response.data;
        $scope.sel = [];
      },
      function(response) {
       $log.warn("Failed to load ports, is the server running?", response.data);
      }
    );
    $http.post("api/configs", {}).then(
      function(response) {
        $scope.configs = response.data;
        $scope.userChoice = "";
      },
      function(response) {
        $log.warn("Failed to load configurations, is the server running?", response.data);
      });
  };

  $scope.saveAs = '';
  $scope.merge = 'replace';
  $scope.refresh();

  $scope.install_link = function() {
    link_params = {'dpid': $scope.sel[0].dpid,
                  'porta': $scope.sel[0].port,
                  'portb': $scope.sel[1].port}
    if('vlan_vid' in $scope.sel[0]) {
        link_params['porta.vlan_vid'] = parseInt($scope.sel[0].vlan_vid);
    }
    if('vlan_vid' in $scope.sel[1]) {
        link_params['portb.vlan_vid'] = parseInt($scope.sel[1].vlan_vid);
    }
    $http.put("api/link", link_params).then(
      function(response) {
        $rootScope.$emit('refresh');
      },
      function(response) {
        $log.warn("Failed to link ports", response.data);
      });
  };

  $scope.isDisabled = function (port) {
    if ($scope.sel.indexOf(port) === -1) {
      if ($scope.sel.length >= 2)
        return true;
      else
        return $scope.sel.length && $scope.sel[0].dpid !== port.dpid;
    } else {
      return false;
    }
  };

  $scope.setSelected = function(port, $event) {
    if ($event.target.tagName == 'INPUT' && $event.target.type == 'text') {
        return
    }
    if ($event.ctrlKey || $event.shiftKey) {
      if ($scope.sel.indexOf(port) === -1)
        $scope.sel = [port];
      else
        $scope.sel = [];
      return;
    }
    if ($scope.isDisabled(port))
      return;
    if ($scope.sel.indexOf(port) === -1) {
      if ($scope.sel.length < 2) {
        $scope.sel.push(port);
      }
    } else {
      $scope.sel.splice($scope.sel.indexOf(port), 1);
    }
  };

  $scope.unlink_port = function() {
    if ($scope.sel[0]) {
      $http.put('api/unlink_port', {'dpid': $scope.sel[0].dpid,
                'port': $scope.sel[0].port}).then(
        function(response) {
          $rootScope.$emit('refresh');
        },
        function(response) {
          $log.warn("Failed to unlink port", response.data);
        });
    }
  };

  $rootScope.$on('refresh', function(event, args) { $scope.refresh(); });

  $scope.select_conf = function() {
    if ($scope.userChoice == false) {
      for (var i in $scope.ports) {
        $scope.ports[i].new_links = [];
      }
      return;
    }
    $http.put("api/load_conf",
              {'dpid': $rootScope.dpid,
               'name': $scope.userChoice,
               'simulate': true,
               'merge': $scope.merge}).then (
      function(response) {
        $scope.new_configs = response.data;
        for (var i in $scope.ports) {
          // Check to so if order is consistent otherwise do a full search
          if ($scope.ports[i].port === response.data[i].port &&
            $scope.ports[i].dpid === response.data[i].dpid) {
              $scope.ports[i].new_links = response.data[i].links;
            } else {
              for (var k in response.data) {
                if ($scope.ports[i].port === response.data[k].port &&
                  $scope.ports[i].dpid === response.data[k].dpid) {
                    $scope.ports[i].new_links = response.data[k].links;
                  }
              }
            }
        }
      },
      function(response) {
        $log.warn("Failed to simulate configuration: " + $scope.userChoice, response.data);
        $scope.userChoice = "";
        for (var i in $scope.ports) {
          $scope.ports[i].new_links = [];
      }
    });
  };

  $scope.load_conf = function() {
    $http.put("api/load_conf",
              {'dpid': $rootScope.dpid,
               'name': $scope.userChoice,
               'simulate': false,
               'merge': $scope.merge}).then(
      function(response) {
        $scope.new_ports = response.data;
        $rootScope.$emit('refresh');
      },
      function(response) {
        $log.warn("Failed to load configuration: " + $scope.userChoice, response.data);
      });
  };

  $scope.save_conf = function() {
    alert("Saving as '" + $scope.saveAs + "'");
    $http.put("api/save_conf", {'name': $scope.saveAs}).then(
      function(response) {
        $scope.refresh();
      },
      function(response) {
        $log.warn("Failed to save configuration: " + $scope.saveAs, response.data);
      });
  };
};

/** Angular controller for tab selection. Hides elements related to a different tab */
var tabsController = function ($scope, $http, $rootScope) {
  $scope.tab = 1;
  $scope.errors = errors;
  // Refresh button in nav
  $scope.refresh = function() {
    $rootScope.$emit("full_refresh");
  };
}

/** Angular controller for links tab, maintains table of links and provides button logic. */
var linksController = function ($scope, $http, $rootScope, $log) {
  $scope.refresh = function() {
    $http.post("api/current_mappings", {'dpid': $rootScope.dpid}).then(
      function(response) {
        $scope.links = response.data;
      },
      function(response) {
        $log.warn("Failed to link mappings, is the server running?", response.data);
      });
  };

  $scope.refresh();

  $scope.compare_items = function(a,b) {
    if ((a.src.port === b.src.port && a.src.vlan === b.src.vlan && a.dst.port === b.dst.port && a.dst.vlan === b.dst.vlan && a.dpid === b.dpid) ||
        (a.dst.port === b.src.port && a.dst.vlan === b.src.vlan && a.src.port === b.dst.port && a.src.vlan === b.dst.vlan && a.dpid === b.dpid)) {
          return true;
        }
    return false;
  };

  $rootScope.$on('refresh', function(event, args) { $scope.refresh(); });

  $scope.click = function (link) {
    var sel = !link.selected;
    for (i in $scope.links) {
      var item = $scope.links[i];
      if ($scope.compare_items(item, link)) {
        item.selected = sel;
      }
    }
  };

  $scope.f_reverse = function(value, index, array) {
    return value.src.port < value.dst.port || $scope.show_rev;
  };

  $scope.unlink = function() {
    for (i in $scope.links) {
      var item = $scope.links[i];
      if (item.selected) {
        $http.put('api/unlink',
                  {"dpid": item.src.dpid,
                   "porta": item.src.port,
                   "porta.vlan_vid": item.src.vlan,
                   "portb": item.dst.port,
                   "portb.vlan_vid": item.dst.vlan}).then(
          (function(item) { return function(response) {
            //$scope.links.splice($scope.links.indexOf(item), 1);
            $rootScope.$emit('refresh');
          }})(item),
          function(response) {
            $log.warn("Failed to unlink port", response.data);
          });
      }
    }
  }
};
