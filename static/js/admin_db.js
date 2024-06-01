function addOption() {
    var select = document.getElementById('dynamicSelect');
    var input = document.getElementById('new_option');
    var newOptionValue = input.value.trim();

    if (newOptionValue) {
        var newOption = document.createElement('option');
        newOption.value = newOptionValue;
        newOption.text = newOptionValue;
        select.appendChild(newOption);
        // Clear the input field
        input.value = '';
    } else {
        alert('Please enter a valid option.');
    }
}

function updateHiddenField() {
    var select = document.getElementById('dynamicSelect');
    var options = Array.from(select.options).map(option => option.value).filter(value => value !== "");
    var hiddenField = document.getElementById('stringfield');
    hiddenField.value = JSON.stringify(options);
}
