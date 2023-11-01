<?php

abstract class CSRF
{
    protected function SessionStarted()
    {
        return session_status() == 2; // 0: DISABLED, 1: NONE, 2: ACTIVE
    }

    protected function CSRFTokenSet()
    {
        if(!$this->SessionStarted())
        {
            throw new Exception("Session must be started before checking if a CSRF token is set.");
        }
        return isset($_SESSION["csrf"]);
    }
}

class CSRFProtection extends CSRF
{
    protected string $CSRFToken;

    public function __construct()
    {
        
        // Check if the session is started, if not start it.

        if(!$this->SessionStarted())
        {
            session_start();
        }
        
        // Check if the Anti-Cross Site Request Forgery token is set. If not, set it.

        if(!$this->CSRFTokenSet())
        {
            $this->CSRFToken = bin2hex(random_bytes(32)); 
            $_SESSION["csrf"] = $this->CSRFToken;
        }
        else // Already set, set it to the session variable.
        {
            $this->CSRFToken = $_SESSION["csrf"];
        }
    }

    public function CSRFToken()
    {
        return $this->CSRFToken;
    }
}
