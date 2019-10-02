//var location=""
//网页加载完执行后面的那个函数
window.onload=function(){
	Drag.init();
	_window_.Here();
}



function windowClose(){
	_window_.quit();
	event.stopPropagation();
}

function windowMin(){
	_window_.minimize();
	event.stopPropagation(); 
}

function windowMax(){
	if ($(".win-content").css("height")=="504px"){
		$(".win-content").css("height","764px");
		}else{
		$(".win-content").css("height","504px");	
		};	
	_window_.changemize();
	event.stopPropagation(); 
}


var Drag = {
	mouseDown:function(e){
		Drag.isDraging = 1;
		Drag.x=e.screenX;
		Drag.y=e.screenY; 
		e.preventDefault();
	},
	mouseUp:function(e){
		Drag.isDraging = null;
		e.preventDefault();
	},
	mouseMove:function(e){
		if(Drag.isDraging){
			var offsetX = e.screenX-Drag.x;
			var offsetY = e.screenY-Drag.y;
			_window_.moveTo(offsetX,offsetY);     //调用了window.py的函数处理，完成move
			Drag.x = e.screenX;
			Drag.y = e.screenY; 
		}
		e.preventDefault();
	},

	mouseOut:function(e){
		var offsetX = e.screenX-Drag.x;
		var offsetY = e.screenY-Drag.y;
		if (offsetX>50 || offsetY>50){
			Drag.isDraging = null;
		}
		else
		{
			_window_.moveTo(offsetX,offsetY); 
			Drag.x = e.screenX;
			Drag.y = e.screenY;
		}	
		e.preventDefault();
	},
	
	init:function(){
		document.onmousedown = Drag.mouseDown;
		document.onmouseup = Drag.mouseUp;
		document.onmousemove = Drag.mouseMove;
	}
};
