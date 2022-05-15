$(document).ready(function(){
    $('#add-entry').validate({
        rules: {
            title: {
                required: true
            },
            text: {
                required: true
            }
        }
    });
})