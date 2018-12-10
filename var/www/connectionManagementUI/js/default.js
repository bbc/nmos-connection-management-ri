var transportParams = {};
var masterEnable = []
var receiverId = "";
var senderId = "";
var root = "http://localhost:8080/x-nmos/connection/v1.0/";

function doInit(){
    checkForSavedRoot();
    transportParams['receiver'] = [];
    transportParams['sender'] = [];
    masterEnable['sender'] = false
    masterEnable['receiver'] = false
    updatePortList('sender');
    updatePortList('receiver');
    $("#api-root-button").click(updateRoot);
}

function checkForSavedRoot(){
    var maybeRoot = localStorage.getItem("root");
    if(maybeRoot){
        root = maybeRoot + "/x-nmos/connection/v1.0/";
        $('#api-root').val(maybeRoot);
    }
}

function updateRoot(){
    var newRoot = $("#api-root").val();
    localStorage.setItem("root", newRoot);
    root = newRoot + "/x-nmos/connection/v1.0/";
    updatePortList('sender');
    updatePortList('receiver');
}

function updateSenderTransportFile(uuid){
    $('#sender-transport-link').attr('href', root + "single/senders/" + uuid + "transportfile/");
    $('#sender-active-type').show();
}

function updatePortList(type){
    var ul = document.getElementById(type + "s-list");
    ul.innerHTML = "";
    doGet(root + 'single/' + type + 's/', function(portList){
        portList.forEach(function(entry, index){
            var li = document.createElement("li");
            li.innerHTML = entry;
            ul.appendChild(li);
            li.onclick = function(){
                updateForm(type, entry);
            }
        });
    });
}

function legChange(type, uuid, paramList){
    var leg = parseInt(document.getElementById(type + '-legs').value);
    var oldLeg = ((leg - 1) * -1) + 1;
    scrapeForm(type, paramList, oldLeg);
    applyParams(type, leg - 1);
}

function updateForm(type, uuid){
    $('#' + type + '-accordion').show();
    $('#' + type + '-enable-form').show();
    var form = document.getElementById(type + 's-form');
    form.childNodes.forEach(function(node){
        if(node.tagName == "DIV" && node.id != (type +  "-update-group") && node.id != (type + "-legs-group")){
            node.style.display = "none";
        }
    });
    doGet(root + "single/" + type + "s/" + uuid + "constraints/", function(constraints){
        var paramList = Object.keys(constraints[0])
        paramList.forEach(function(param){
            var div = document.getElementById(type + "-" + param + "-group");
            div.style.display = "inline";
        });
        var legselect = document.getElementById(type + '-legs');
        legselect.onchange = function(){
            legChange(type, uuid, paramList);
        }
        getParamList(type, uuid, paramList, 0);
        if(type == "sender"){
            $('#sender-receiver_id-group').show();
        }else{
            $('#receiver-sender_id-group').show();
            getTransportFile(uuid);
            $('#receiver-update-tf').click(function(){
                stageTransportFile(uuid);
            });
        }
        $('#' + type + '-legs-group').show();
        $('#' + type + '-update-group').show();
        updateSenderTransportFile(uuid);
        setupActivates(type, uuid);
        getActiveTransportParams(type, uuid);
    });
}

function getTransportFile(uuid){
    url = root + "single/receivers/" + uuid + "staged";
    doGet(url, function(response){
        console.log(response)
        transportFile = response.transport_file
        $('#receiver-tf-type').val(transportFile.type);
        $('#receiver-tf-data').val(transportFile.data);
    });
}

function stageTransportFile(uuid){
    var message = {};
    senderId = $('#receiver-tf-senderid').val();
    $('#receiver-sender_id').val(senderId);
    message.transport_file = {};
    message.transport_file.type = $('#receiver-tf-type').val();
    message.transport_file.data = $('#receiver-tf-data').val();
    if(senderId == ""){
        message.sender_id = null;
    }else{
        message.sender_id = senderId;
    }
    url = root + "single/receivers/" + uuid + "staged";
    doPatch(message, url , function(code, response){
        updateForm('receiver', uuid);
        if(code == 200){
            $('#receiver-tf-success').show().delay(2000).fadeOut(1000);
        }else{
            $('#receiver-tf-fail-alert-text').text(response.error);
            $('#receiver-tf-failure').show().delay(2000).fadeOut(1000);
        }
    });
}

function setupActivates(type, uuid){
    $('#' + type + '-activate-now').off('click');
    $('#' + type + '-activate-now').click(function(){
        activate(type, "now", uuid);
    });
    $('#' + type + '-activate-relative').off('click');
    $('#' + type + '-activate-relative').click(function(){
        activate(type, "relative", uuid);
    });
    $('#' + type + '-activate-absolute').off('click');
    $('#' + type + '-activate-absolute').click(function(){
        activate(type, "absolute", uuid);
    });
}

function activate(type, mode, uuid){
    var message = {};
    if(mode == "now"){
        message.mode = "activate_immediate";
    }else{
        console.log(mode);
        var secs;
        var nanos;
        if(mode != "relative"){
            message.mode = "activate_scheduled_absolute";
            secs = $('#' + type + '-activate-absolute-secs').val();
            nanos = $('#' + type + '-activate-absolute-nanos').val();
        }else{
            secs = $('#' + type + '-activate-relative-secs').val();
            nanos = $('#' + type + '-activate-relative-nanos').val();
            message.mode = "activate_scheduled_relative";
        }
        message.requested_time = secs + ":" + nanos;
    }
    toSend = {}
    toSend['activation'] = message
    doPatch(
        toSend, 
        root + "single/" + type + "s/" + uuid + "staged",
        function(code, response){
            activationCallback(type, code, response.activation);
            getActiveTransportParams(type, uuid);
        }
    );
}

function activationCallback(type, code, response){
    if(code == 200 || code == 202){
        if(code == 200){
            $('#' + type + '-activate-success-text').text("Activation successful");
        }else{
            $('#' + type + '-activate-success-text').text("Activation scheduled for " + response.activation_time)
        }
        $('#' + type + '-activate-success').show().delay(2000).fadeOut(1000);
    }else{
        $('#' + type + '-activate-failure-text').text(response.error);
        $('#' + type + '-activate-failure').show().delay(2000).fadeOut(1000);        
    }
}

function getParamList(type, uuid, paramList, leg){
    if(type == "sender"){
        url = root + "single/senders/" + uuid + "staged/";
    }else{
        url = root + "single/receivers/" + uuid + "staged/";
    }
    doGet(url, function(port){
        var select = document.getElementById(type + "-legs");
        select.innerHTML = "";
        var option = document.createElement("option");
        option.innerHTML = "1";
        select.appendChild(option);
        numLegs = port.transport_params.length;
        if(numLegs > 1){
            var option = document.createElement("option");
            option.innerHTML = "2";
            select.appendChild(option);
        }else{
            leg = 0
        }
        transportParams[type] = port.transport_params;
        masterEnable[type] = port.master_enable;
        if(type == "sender"){
            receiverId = port.receiver_id;
        }else{
            senderId = port.sender_id;
        }
        updateConstrainedFields(type, uuid, leg, function(){
            applyParams(type, leg);
            var button = document.getElementById(type + '-update-button');
            button.onclick = function(){
                buttonClick(type, uuid, paramList, numLegs);
            }
        });
    });
}

function updateConstrainedFields(type, uuid, leg, callback){
    doGet(root + "single/" + type + "s/" + uuid + "constraints/", function(constraints){
        if(type == "receiver"){
            populateReceiverInterfaceList(constraints, leg, callback);
        }else{
            populateSenderSourceList(constraints, leg, callback)
        }   
    });
}

function populateReceiverInterfaceList(constraints, leg, callback){
    select = $('#receiver-interface_ip')[0]
    select.innerHTML = ""
    for(var i = 0; i < constraints[leg]['interface_ip']['enum'].length; i++){
        var option = document.createElement("option")
        option.innerHTML = constraints[leg]['interface_ip']['enum'][i]
        select.appendChild(option)
    }
    var option = document.createElement("option")
    option.innerHTML = "auto"
    select.appendChild(option)
    callback()
}

function populateSenderSourceList(constraints, leg, callback){
    select = $('#sender-source_ip')[0]
    select.innerHTML = ""
    for(var i = 0; i < constraints[leg]['source_ip']['enum'].length; i++){
        var option = document.createElement("option")
        option.innerHTML = constraints[leg]['source_ip']['enum'][i]
        select.appendChild(option)
    }
    var option = document.createElement("option")
    option.innerHTML = "auto"
    select.appendChild(option)
    callback()
}

function applyParams(type, leg){
    var tp = transportParams[type][leg]
    for(key in tp){
        if (tp.hasOwnProperty(key)){
            var input = document.getElementById(type + "-" + key)
            console.log(key)
            if(key == "rtp_enabled"){
                input.checked = tp[key];
            }else if(key == "fec_enabled"){
                input.checked = tp[key];
            }else{
                input.value = tp[key];
            }
        }
    }
    enable = document.getElementById(type + "-master_enable")
    enable.checked = masterEnable[type]
    if(type == "sender"){
        $('#sender-receiver_id')[0].value = receiverId;
    }else{
        $('#receiver-sender_id')[0].value = senderId;
    }
}

function displayPort(type, uuid){
    if(type == "receivers"){
        var endpoint = "transportparams/"
    }else{
        var endpoint = ""
    }
    doGet(root + "single/" + type + "/" + uuid + "staged/" + endpoint, function(device){
        var div = document.getElementById(type + "-details");
        div.innerHTML = JSON.stringify(device);
    });
}

function doPost(request, url, callback){
    http = new XMLHttpRequest();
    http.open("POST", url, true);
    http.setRequestHeader("Content-type", "application/json");
    http.onreadystatechange = function(){
        if(http.readyState == 4){
            callback(http.status, JSON.parse(http.responseText));
        }
    }
    http.send(JSON.stringify(request, null, 2));
}

function doPut(request, url, callback){
    http = new XMLHttpRequest();
    http.open("PUT", url, true);
    http.setRequestHeader("Content-type", "application/json");
    http.onreadystatechange = function(){
        if(http.readyState == 4){
            callback(http.status, http.responseText);
        }
    }
    http.send(JSON.stringify(request, null, 2));
}

function doPatch(request, url, callback){
    http = new XMLHttpRequest();
    http.open("PATCH", url, true);
    http.setRequestHeader("Content-type", "application/json");
    http.onreadystatechange = function(){
        if(http.readyState == 4){
            callback(http.status, JSON.parse(http.responseText));
        }
    }
    http.send(JSON.stringify(request, null, 2));
}

function doGet(url, callback){
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", url, true);
    xmlHttp.setRequestHeader("Content-type", "application/json");
    xmlHttp.onreadystatechange = function() { 
        if (xmlHttp.readyState == 4 && xmlHttp.status == 200)
            callback(JSON.parse(xmlHttp.responseText));
    }
    xmlHttp.send(null);
}

function scrapeForm(type, paramsList, leg){
    for (var i = 0, len = paramsList.length; i < len; i++){
        var element = paramsList[i];
        var input = document.getElementById(type + '-' + element);
        if(element.search("port") > 0){
            if(input.value == "auto"){
                transportParams[type][leg][element] = input.value;
            }else{
                transportParams[type][leg][element] = parseInt(input.value);
            }
        }else if(element == "fec_block_width" || element == "fec_block_height"){
            transportParams[type][leg][element] = parseInt(input.value);            
        }else{
            if(element == "rtp_enabled"){
                transportParams[type][leg][element] = input.checked;
            }else if(element == "fec_enabled"){
                transportParams[type][leg][element] = input.checked;
            }else if(element == "rtcp_enabled"){
                transportParams[type][leg][element] = input.checked;
            }else if(element == "multicast_ip" || element == "source_ip" || element == "dest_ip"){
                if(input.value == ""){
                    transportParams[type][leg][element] = null;
                }else{
                    transportParams[type][leg][element] = input.value;
                }
            }else{
                transportParams[type][leg][element] = input.value;
            }
        }
        enable = $("#" + type + "-master_enable")[0]
        masterEnable[type] = enable.checked
        if(type == "sender"){
            receiverId = $('#sender-receiver_id')[0].value;
        }else{
            senderId = $('#receiver-sender_id')[0].value;
        }
        if(receiverId == ""){
            receiverId = null
        }
        if(senderId == ""){
            senderId = null
        }
    }
}

function buttonClick(type, uuid, paramList, numLegs){
    var legInput = document.getElementById(type + '-legs');
    var leg = parseInt(legInput.value) - 1;
    scrapeForm(type, paramList, leg);
    var message = {};
    message.transport_params = [];
    for(var i = 0; i < numLegs; i++){
        message.transport_params[i] = transportParams[type][i];
    }
    message.master_enable = masterEnable[type]
    if(type == "sender"){
        if(receiverId != ""){
            message.receiver_id = receiverId;
        }else{
            message.receiver_id = null;
        }
        var url = root + 'single/senders/' + uuid + 'staged';
    }else{
        if(senderId != ""){
            message.sender_id = senderId;
        }else{
            message.sender_id = null;
        }
        var url = root + 'single/receivers/' + uuid + 'staged';
    }
    doPatch(message, url, function(status, response){
        if(status == 200){
            Ok(type);
        }else{
            fail(type, response['error']);
        }
    });
}

function Ok(type){
    $('#' + type + '-success').show().delay(2000).fadeOut(1000);
}

function fail(type, message){
    $('#' + type + '-fail-alert-text').text(message);
    $('#' + type + '-failure').show().delay(20000).fadeOut(1000);
}

function getActiveTransportParams(type, uuid){
    if(type == "sender"){
        var url = root + 'single/senders/' + uuid + 'active/';
    }else{
        var url = root + 'single/receivers/' + uuid + 'active/';
    }
    $('#' + type + '-active-params').html("");
    $('#' + type + '-active-params-refresh').unbind("click");
    $('#' + type + '-active-params-refresh').click(function(){
        getActiveTransportParams(type, uuid);
    });
    doGet(url, function(response){
        var div = $('#' + type + '-active-params');
        enable = response.master_enable;
        var p = document.createElement("p");
        p.innerHTML = "<span class='strong'>master_enable:</span> " + enable;
        div.append(p);
        for(var outerKey in response.transport_params){
            transport_params = response.transport_params[outerKey];
            var h3 = document.createElement("h3");
            $(h3).text("Leg " + outerKey);
            div.append(h3);
            for(var key in transport_params){
                var p = document.createElement("p");
                p.innerHTML = "<span class='strong'>" + key + ":</span> " + transport_params[key];
                div.append(p);
            }
            
        }
    });
}
