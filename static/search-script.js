$(document).ready(function(){
    $("#search_input").keyup(function(){
    var text = $(this).val();

    $.ajax({
      url: "/",
      type: "get",
      data: {text: text, triggered: 1},
      success: function(response) {
        console.log(response)
        var obj = JSON.parse(response)
        var result = obj.result
        console.log(result)
        console.log(result[0])
        var myNode = document.getElementById("entries");
            while (myNode.firstChild) {
                myNode.removeChild(myNode.firstChild);
            }
        for (i=0; i<result.length; i++) {
            console.log(result[i])
            console.log(result[i].title)
            console.log(result[i].tagline)

            $("#entries").append("<li><a href='/download/" + result[i].path + "'><h2>" + result[i].title + "</h2></a>" + result[i].tagline);

        }
      },
      error: function(xhr) {
        console.log(xhr)
      }
    });
});
})