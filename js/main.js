
$(function(){
	contactRefresh("choose-file-list");
	getNIC();
});


//协议分析标签
function contactClassClick(li,id){
	$(".contact-list:visible").hide();
	var el = $("#"+id);
	el.show();
	$(".contact-class label").removeClass("tc-select");
	$(li).addClass("tc-select");
	if(!el.attr("isLoaded")){
		contactRefresh();
	}
}


//刷新协议分析
function contactRefresh(id){
	var list = id?$("#"+id):$(".contact-list:visible");
	var id = list.attr("id");
	
	var callback = function(data){
		var ul = list.find(">ul");
		ul[0].scrollTop=0;
		ul.html(data);
	};
	if(id==="choose-file-list"){
		_contact_.getChooseList(callback);
	}
	list.attr("isLoaded",1).attr("pageIndex",0);
}


function wa(id){
	$("#startcap").attr("src","../imgs/startwa.png");
	$("#startcap").attr("title","停止抓包");
	$("#startcap").attr("onclick","stopCap()");	
	parent._window_.stopCap();
	var files=parent._window_.wa($("#nicName option:selected").attr("value")+"-"+$("#nicType option:selected").attr("value"));
	if (files=="NULL"){
		return;	
	};
	var ul = $("#"+id+">ul");
	ul[0].scrollTop=0;
	contactClassClick(".contact-class label:first",id);
	readCap(id);
	int=self.setInterval("readCap('"+id+"')",1000);
}


function readCap(id){
	var filess=parent._window_.readCap();
	if (filess=="NULL"){
		return;	
	};
	var ul = $("#"+id+">ul");
	ul[0].scrollTop=0;
	ul.html(filess);
}


function stopCap(){
	var filess=parent._window_.stopCap();
	if (filess=="NULL"){
		return;	
	};
	int=window.clearInterval(int);
	readCap("process-cap");
	$("#startcap").attr("src","../imgs/wa.png");
	$("#startcap").attr("title","开始抓包");
	$("#startcap").attr("onclick","wa('process-cap')");	
}

function updateSource(){
	var mlist=[];
	$.each($(".Capchoose>input:checked"),function(n,ele){
		mlist.push(ele.id);
	});	
	var updResult=parent._window_.updateSource(mlist);	
}


function addFiles(){
	var files=parent._window_.addFiles();
	aboutFiles(files);
}


function delCap(id){
	var files=parent._window_.delCap(id.split("<td>")[0]);
	aboutFiles(files);
}


function addCap(){
	var files=parent._window_.addCap();
	aboutFiles(files);
}


function aboutFiles(files){
	if (files=="NULL"){
		return;	
	};
	var strs=new Array();
	strs=files.split("|");
	var content=[];
	content.push("<table>");
	for(i=0;i<strs.length;i++)
	{
		if(strs!=""){
			content.push("<tr><td><img src='../imgs/del_cap.png' style='width:25px' id='"+strs[i]+"' title='删除' onclick='delCap(this.id)' /></td><td>"+strs[i]+"</td><td><div class='wireshark' id='PCAP_"+strs[i].split("<td>")[0]+"' onclick=openPcap(this.id)></div></td></tr>");
		}
	}
	content.push("<td><img src='../imgs/add_cap.png' style='width:25px' title='增加' onclick='addCap()' /></td><td>增加包文件</td><td></td><td></td></table>");
	var ul = $("#choose-file-list >ul");
	ul[0].scrollTop=0;
	ul.html(content.join(""));
	contactClassClick(".contact-class label:eq(1)",'choose-file-list');
}


function startAna(id){
	var anaResult=parent._window_.startAna();
	$("#ana").attr("src","../imgs/start.png");
	$(".contact-list:visible").hide();

	var el = $("#"+id);
	el.show();
	$(".contact-class label").removeClass("tc-select");
	$("label").next().addClass("tc-select");
	var ul = $("#"+id).find(">ul");
	ul[0].scrollTop=0;
	ul.html(anaResult);
}


function sortNode(vl,sid){
	ul = $("#"+sid).find(">ul");
	var sortResult=parent._window_.doSort(vl);
	ul[0].scrollTop=0;
	ul.html(sortResult);
}

function sortSession(vl,sid){
	ul = $("#"+sid).find(">ul");
	var sortResult=parent._window_.doSessionSort(vl);
	ul[0].scrollTop=0;
	ul.html(sortResult);
}


function openPcap(sid){
	var openResult=parent._window_.openPcap(sid);
}


function getNIC(){
	ul = $("#nicName");
	showResult=parent._window_.showNIC();
	if (showResult=="")
	{
		Boxy.confirm("QPA需要安装winpcap才能抓包，现在开始安装？",function(){
			parent._window_.installWinPcap();
			ul.html(parent._window_.showNIC());
		});
	}else{
		ul.html(showResult);
	}
}