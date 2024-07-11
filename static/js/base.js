// Save scroll position
function saveScrollPosition() {
    const scrollPos = window.scrollY;
    localStorage.setItem('scrollPos', scrollPos);
}

// Restore scroll position
function restoreScrollPosition() {
    const scrollPos = localStorage.getItem('scrollPos');
    if (scrollPos) {
        window.scrollTo(0, parseInt(scrollPos));
        localStorage.removeItem('scrollPos'); // Clear stored scroll position
    }
}

// Set up event listeners on page load
window.addEventListener('load', function () {
    restoreScrollPosition();

    // Attach saveScrollPosition to all forms on the page
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', saveScrollPosition);
    });
});
