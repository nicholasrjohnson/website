// Please see documentation at https://docs.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.

$(document).ready( function() {

    function highlightMenuItems( arg1, arg2) {
        var topMenuItem  = arg1;
        var sideMenuItem = arg2;
        var objectElement1 = document.getElementById(topMenuItem);
        var objectElement2 = document.getElementById(sideMenuItem);
        objectElement1.style.color = "#76a3fb"; 
        objectElement2.style.color = "#76a3fb"; 
    };

});