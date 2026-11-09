document.addEventListener("DOMContentLoaded", function () {
    const printButton = document.getElementById("print-report");
    if (printButton) {
        printButton.addEventListener("click", function () {
            window.print();
        });
    }
});
