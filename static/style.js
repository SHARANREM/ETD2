// Function to read the content of a file and execute a callback with the result
function readFileContent(file, callback) {
    const reader = new FileReader();
    reader.onload = function (event) {
        callback(event.target.result);
    };
    reader.readAsText(file);
}

// Function to get the selected encryption or decryption algorithms (shields) based on a prefix
function getSelectedAlgorithms(prefix) {
    const selected = [];

    // Checkboxes for various algorithm options
    if (document.getElementById(prefix + "AES")?.checked) selected.push("aes");
    if (document.getElementById(prefix + "RSA")?.checked) selected.push("rsa");
    if (document.getElementById(prefix + "XOR")?.checked) selected.push("xor");
    if (document.getElementById(prefix + "Caesar")?.checked) selected.push("caesar");
    if (document.getElementById(prefix + "Base64")?.checked) selected.push("base64");
    if (document.getElementById(prefix + "Reverse")?.checked) selected.push("reverse");
    if (document.getElementById(prefix + "Vigenere")?.checked) selected.push("vigenere");

    return selected;
}

// Handle encryption submit button click
document.getElementById("encryptSubmit").addEventListener("click", async function () {
    const textArea = document.getElementById("encryptData");
    const password = prompt("Enter a strong password for encryption:");
    const xorKey = prompt("Enter a another password to validate password:");
    const fileInput = document.getElementById("encryptFile");
    const algorithms = getSelectedAlgorithms("shield");

    // Validate password inputs
    if (!password || !xorKey || isNaN(parseInt(xorKey))) {
        alert("Encryption password and validate password are required!");
        return;
    }

    const payload = { password, xor_key: parseInt(xorKey), algorithms };

    // Handle file or text input for encryption
    if (fileInput.files.length > 0) {
        readFileContent(fileInput.files[0], async function (fileText) {
            await encryptText(fileText, payload);
        });
    } else if (textArea.value.trim()) {
        await encryptText(textArea.value.trim(), payload);
    } else {
        alert("Please enter text or upload a file to encrypt.");
    }
});

// Function to handle encryption request to the server
async function encryptText(text, payload) {
    const response = await fetch("/encrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, ...payload }),
    });

    const data = await response.json();

    // Check for error response from server
    if (!response.ok || data.error) {
        alert(data.error || "Encryption failed due to an unknown error.");
        return;
    }

    // Download encrypted text as a file
    const blob = new Blob([data.encrypted_text], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "encrypted_data.txt";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}


// Handle decryption submit button click
document.getElementById("decryptSubmit").addEventListener("click", async function () {
    const textArea = document.getElementById("decryptData");
    const password = prompt("Enter your decryption password:");
    const xorKey = prompt("Enter your Validate password:");
    const fileInput = document.getElementById("decryptFile");
    const algorithms = getSelectedAlgorithms("dshield");

    // Validate password inputs
    if (!password || !xorKey || isNaN(parseInt(xorKey))) {
        alert("Decryption password and Validate password are required!");
        return;
    }

    const payload = { password, xor_key: parseInt(xorKey), algorithms };

    // Handle file or text input for decryption
    if (fileInput.files.length > 0) {
        readFileContent(fileInput.files[0], async function (fileText) {
            await decryptText(fileText, payload);
        });
    } else if (textArea.value.trim()) {
        await decryptText(textArea.value.trim(), payload);
    } else {
        alert("Please enter encrypted text or upload a file to decrypt.");
    }
});

// Function to handle decryption request to the server
async function decryptText(text, payload) {
    const response = await fetch("/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, ...payload }),
    });

    const data = await response.json();

    // Check for invalid password or corrupted data
    if (data.decrypted_text === "Invalid Key or Data!") {
        alert("Decryption failed! Incorrect password or corrupted data.");
        return;
    }

    // Download decrypted text as a file
    const blob = new Blob([data.decrypted_text], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "decrypted_data.txt";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}
