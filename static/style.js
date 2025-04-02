// Read file content
function readFileContent(file, callback) {
    const reader = new FileReader();
    reader.onload = function (event) {
        callback(event.target.result);
    };
    reader.readAsText(file);
}

// Encryption
document.getElementById("encryptSubmit").addEventListener("click", async function () {
    const textArea = document.getElementById("encryptData");
    const password = prompt("Enter a strong password for encryption:");
    const fileInput = document.getElementById("encryptFile");

    if (!password) {
        alert("Encryption password is required!");
        return;
    }

    if (fileInput.files.length > 0) {
        readFileContent(fileInput.files[0], async function (fileText) {
            await encryptText(fileText, password);
        });
    } else if (textArea.value.trim()) {
        await encryptText(textArea.value.trim(), password);
    } else {
        alert("Please enter text or upload a file to encrypt.");
    }
});

// Function to send text for encryption
async function encryptText(text, password) {
    const response = await fetch("/encrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: text, password: password }),
    });

    const data = await response.json();

    // Download encrypted file
    const blob = new Blob([data.encrypted_text], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "encrypted_data.txt";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Decryption
document.getElementById("decryptSubmit").addEventListener("click", async function () {
    const textArea = document.getElementById("decryptData");
    const password = prompt("Enter your decryption password:");
    const fileInput = document.getElementById("decryptFile");

    if (!password) {
        alert("Decryption password is required!");
        return;
    }

    if (fileInput.files.length > 0) {
        readFileContent(fileInput.files[0], async function (fileText) {
            await decryptText(fileText, password);
        });
    } else if (textArea.value.trim()) {
        await decryptText(textArea.value.trim(), password);
    } else {
        alert("Please enter encrypted text or upload an encrypted file.");
    }
});

// Function to send text for decryption
async function decryptText(text, password) {
    const response = await fetch("/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: text, password: password }),
    });

    const data = await response.json();
    if (data.decrypted_text === "Invalid Key or Data!") {
        alert("Decryption failed! Incorrect password or corrupted data.");
        return;
    }

    // Download decrypted file
    const blob = new Blob([data.decrypted_text], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "decrypted_data.txt";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}
