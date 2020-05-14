<?php

namespace AdactiveSas\Saml2BridgeBundle\Exception;

use AdactiveSas\Saml2BridgeBundle\Entity\ServiceProvider;
use Symfony\Component\Security\Core\Exception\AccessDeniedException as SymfonyAccessDeniedException;

class UserNotAllowedInServiceProvider extends SymfonyAccessDeniedException implements Exception
{

    private $sp;

    /**
     * Constructor.
     * @param string $message
     * @param \Throwable|null $previous
     * @param ServiceProvider|null $sp
     */
    public function __construct(string $message = 'User not allowed to login in Service Provider.', \Throwable $previous = null, ServiceProvider $sp = null)
    {
        parent::__construct($message, $previous);
        $this->sp = $sp;
    }

    /**
     * @return null|ServiceProvider|null
     */
    public function getServiceProvider() {
        return $this->sp;
    }

}
