// script.aculo.us scriptaculous.js v1.6.4, Wed Sep 06 11:30:58 CEST 2006
// Copyright (c) 2005 Thomas Fuchs (http://script.aculo.us, http://mir.aculo.us)

var Scriptaculous={
Version:'1.6.4',
require:function(libraryName){
document.write('<script type="text/javascript" src="'+libraryName+'"></script>');
},
load:function(){
if((typeof Prototype=='undefined')||
(typeof Element=='undefined')||
(typeof Element.Methods=='undefined')||
parseFloat(Prototype.Version.split(".")[0]+"."+
Prototype.Version.split(".")[1])<1.5)
throw("script.aculo.us requires the Prototype JavaScript framework >= 1.5.0");
$A(document.getElementsByTagName("script")).findAll(function(s){
return(s.src&&s.src.match(/scriptaculous\.js(\?.*)?$/))
}).each(function(s){
var path=s.src.replace(/scriptaculous\.js(\?.*)?$/,'');
var includes=s.src.match(/\?.*load=([a-z,]*)/);
(includes?includes[1]:'builder,effects,dragdrop,controls,slider').split(',').each(
function(include){Scriptaculous.require(path+include+'.js')});
});
}
}
Scriptaculous.load();