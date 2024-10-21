        // Get all sidebar links
        const sidebarLinks = document.querySelectorAll('.nav-link2');
        let previousSection = null; // To store the previously clicked section

        // Add event listeners to all links
        sidebarLinks.forEach(link => {
            link.addEventListener('click', function (event) {
                // Get the target id from the data-target attribute
                const targetId = this.getAttribute('data-target');

                // If there is a previously clicked section, reset its background color
                if (previousSection) {
                    previousSection.style.backgroundColor = ''; // Reset to default background
                }

                // Get the new target section and apply the background color
                const targetSection = document.getElementById(targetId);
                if (targetSection) {
                    targetSection.style.backgroundColor = 'lightyellow';  // New background color on click
                    // Use the CSS variable for the highlight color
                    // {#const highlightColor = getCssVariableValue('--content-sub-parts');#}
                    // {#targetSection.style.backgroundColor = highlightColor;#}
                }

                // Update the previousSection to the currently clicked section
                previousSection = targetSection;
            });
        });
