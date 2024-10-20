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


function removeOption() {
    var select = document.getElementById('dynamicSelect');

    if (select.selectedIndex !== -1) {
        // Remove the selected option
        select.remove(select.selectedIndex);
    } else {
        alert('Please select an option to remove.');
    }
}


function updateHiddenField() {
    var select = document.getElementById('dynamicSelect');
    var options = Array.from(select.options).map(option => option.value).filter(value => value !== "");
    var hiddenField = document.getElementById('stringfield');
    hiddenField.value = JSON.stringify(options);
}


function updateThresholdHiddenField() {
    var rangeInput = document.getElementById('threshold');
    var hiddenInput = document.getElementById('hiddenThreshold');
    hiddenInput.value = rangeInput.value;
}


function confirmDelete() {
    // Get the selected collection name from the form
    var collection = document.querySelector('select[name="data_collection"]').value;

    // Display a confirmation dialog with the collection name
    return confirm("آیا از حذف مجموعه داده " + collection + " مطمئن هستید؟ این عمل غیر قابل بازگشت است.");
}