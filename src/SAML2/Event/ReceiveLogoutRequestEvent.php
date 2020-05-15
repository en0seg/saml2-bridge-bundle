<?php

/**
 * Copyright 2017 Adactive SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace AdactiveSas\Saml2BridgeBundle\SAML2\Event;

use AdactiveSas\Saml2BridgeBundle\Entity\HostedIdentityProvider;
use AdactiveSas\Saml2BridgeBundle\SAML2\State\SamlStateHandler;
use SAML2\LogoutRequest;
use Symfony\Component\EventDispatcher\Event;

class ReceiveLogoutRequestEvent extends Event
{
    /**
     * @var HostedIdentityProvider
     */
    protected $hostedIdentityProvider;

    /**
     * @var SamlStateHandler
     */
    protected $samlStateHandler;

    /**
     * @var LogoutRequest
     */
    protected $logoutRequest;

    /**
     * LogoutEvent constructor.
     *
     * @param LogoutRequest $logoutRequest
     * @param HostedIdentityProvider $hostedIdentityProvider
     * @param SamlStateHandler $samlStateHandler
     */
    public function __construct(
        LogoutRequest $logoutRequest,
        HostedIdentityProvider $hostedIdentityProvider,
        SamlStateHandler $samlStateHandler
    ) {
        $this->hostedIdentityProvider = $hostedIdentityProvider;
        $this->samlStateHandler = $samlStateHandler;
        $this->logoutRequest = $logoutRequest;
    }

    /**
     * @return HostedIdentityProvider
     */
    public function getHostedIdentityProvider()
    {
        return $this->hostedIdentityProvider;
    }

    /**
     * @return SamlStateHandler
     */
    public function getSamlStateHandler()
    {
        return $this->samlStateHandler;
    }

    /**
     * @return LogoutRequest
     */
    public function getLogoutRequest()
    {
        return $this->logoutRequest;
    }
}
