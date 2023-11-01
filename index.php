<?php

require("csrf.php");

$CSRF = new CSRFProtection();

abstract class Encryption
{
    
    private string $InitializationVector;
    private string $Key; 
    
    public function __construct($iv, $key)
    {
    
        if($_SERVER["REQUEST_METHOD"] != "POST")
        {
            http_response_code(400);
            echo json_encode(["bad request" => "Only POST requests are accepted to this endpoint."]);
            exit();
        }

        $this->InitializationVector = $iv;
        $this->Key = $key;

        // Verify Anti-Cross Site request forgery token is the same as sessions

        if(!isset($_POST["csrftoken"]))
        {
            http_response_code(403);
            echo json_encode(["Forbidden" => "No CSRF token passed."]);
            exit();
        }

        if($_POST["csrftoken"] != $_SESSION["csrf"])
        {
            http_response_code(403);
            echo json_encode(["Forbidden" => "Incorrect CSRF token."]);
            exit();
        }
    }

    protected function EncryptMessage($message)
    {
        return openssl_encrypt($message, "AES-128-CTR", $this->Key, 0, $this->InitializationVector);
    }

    protected function DecryptMessage($message)
    {
        return openssl_decrypt($message, "AES-128-CTR", $this->Key, 0, $this->InitializationVector);
    }

    protected function SanitizeMessage($message)
    {
        return htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); // Sanitize input, otherwise a user can decrypt an encrypted xss payload and it be executed
    }
}

class EncryptionFunctions extends Encryption 
{
    private array $Actions = array("encrypt", "decrypt"); // whitelisted actions
    private string $Message;

    private function SetEncrypted($status)
    {
        $_SESSION["encrypted"] = $status;
    }

    private function IsEncrypted()
    {
        return $_SESSION["encrypted"];
    }

    function ServeAction()
    {      
        if(!isset($_POST["action"]))
        {
            http_response_code(400);
            echo json_encode(["bad request" => "No action POST parameter sent."]);
            exit();
        }

        $Action = strtolower($_POST["action"]);
        
        if(!in_array($Action, $this->Actions))
        {
            echo json_encode(["bad request" => "Invalid action."]);
            exit();
        }

        if($Action == "encrypt" || $Action == "decrypt")
        {
            if(!isset($_POST["message"]))
            {
                http_response_code(400);
                echo json_encode(["bad request" => "Encryption methods need the message POST parameter sent."]);
                exit();
            }
            $this->Message = $_POST["message"];
        }
        
        $output = "";

        switch ($Action) {
            case "encrypt":
                
                // verify message hasnt already been encrypted and initialization vector being reused

                if($this->IsEncrypted())
                {
                    exit();
                }

                $output = $this->EncryptMessage($this->Message);
                $this->SetEncrypted(true);
                break;

            case "decrypt":
                $output = $this->SanitizeMessage($this->DecryptMessage($this->Message)); // Sanitize decrypted message from XSS Injection.
                
                // unregister the initialization vector, the next time this class is invoked it will generate a new initialization vector
                
                unset($_SESSION["iv"]);

                // untoggle encryption
                $this->SetEncrypted(false);
                break;

            default:
                http_response_code(500);
                exit(); // Shouldn't reach this code.
                break;
        }
        echo json_encode(["success" => $output]);
        exit();
    }
}

if($_SERVER["REQUEST_METHOD"] == "POST")
{
    // Generate a secure initialization vector

    $iv_set = isset($_SESSION["iv"]);

    // if the iv is set to a session variable, set the encryption iv to the session variable. otherwise generate one.

    $encryption_iv = $iv_set ? $_SESSION["iv"] : random_bytes(openssl_cipher_iv_length("AES-128-CTR"));

    // if the initialization vector wasnt assigned to a session variable then assign it

    if(!$iv_set)
    {
        $_SESSION["iv"] = $encryption_iv;
    }

    // start encryption

    $Encryption = new EncryptionFunctions("EncryptionKey", $encryption_iv);
    $Encryption->ServeAction();
}


?>

<!DOCTYPE html>
<html>
    <head>
        <title>Encryption</title>
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
    </head>
    <body>
        <form action="index.php" id="EncryptionForm" method="POST">
            <input name="message" placeholder="Message to encrypt/decrypt: ">
            <input name="csrftoken" value=<?php echo "\"" . $_SESSION["csrf"] . "\""; ?> hidden>
            <button id="Encrypt" type="submit">Encrypt</button>
            <button id="Decrypt" type="submit">Decrypt</button>
        </form>
        <p id="output"></p>
    </body>

    <script>

        $("#Encrypt").click(function()
        {
            $(this).data('clicked', true);
        });

        $("#Decrypt").click(function()
        {
            $(this).data('clicked', true);
        });
        

        document.querySelector("#EncryptionForm").addEventListener('submit', function(e) {
        
            e.preventDefault(); 

            let action = "";


            let message = $("input[name=message]").val();
            let csrf = $("input[name=csrftoken]").val()

            if($("#Encrypt").data("clicked"))
            {
                action = "encrypt"
                $("#Encrypt").data("clicked", false)
            }
            else
            {
                action = "decrypt"
                $("#Decrypt").data("clicked", false)
            }

            let key = "";

            $.post('index.php', { 
                action: action, 
                message: message, 
                csrftoken: csrf
            }, 
            function(returnedData){
                JSONResponse = JSON.parse(returnedData);
                key = Object.keys(JSONResponse)[0]

                if(action == "encrypt")
                {
                    document.getElementById("output").innerText = "Encrypted Message: " + JSONResponse[key]    
                }
                else
                {
                    document.getElementById("output").innerText = "Decrypted Message: " + JSONResponse[key]    
                }
                        
            }).fail(function(response){
                let ResponseJSON = JSON.parse(response.responseText)
                key = Object.keys(ResponseJSON)[0] 
                alert(ResponseJSON[key])
            });
        });

    </script>
</html>
