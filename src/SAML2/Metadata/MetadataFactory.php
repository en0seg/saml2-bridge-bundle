<?php

/**
 * Copyright 2014 SURFnet bv
 *
 * Modifications copyright (C) 2017 Adactive SAS
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

namespace AdactiveSas\Saml2BridgeBundle\SAML2\Metadata;


use AdactiveSas\Saml2BridgeBundle\Entity\HostedEntities;
use SAML2\Certificate\KeyLoader;
use SAML2\Utilities\Certificate;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Twig\Environment;

class MetadataFactory
{
    /**
     * @var \Symfony\Component\Templating\EngineInterface
     */
    private $twig;

    /**
     * @var HostedEntities
     */
    private $hostedEntities;

    /**
     * MetadataFactory constructor.
     * @param Environment $twig
     * @param HostedEntities $hostedEntities
     */
    public function __construct(
        Environment $twig,
        HostedEntities $hostedEntities
    ) {
        $this->twig = $twig;
        $this->hostedEntities = $hostedEntities;
    }

    /**
     * @return Response
     */
    public function getMetadataResponse()
    {
        $response = new Response();
        try {
            $response->setContent(
                $this->twig->render(
                    "@AdactiveSasSaml2Bridge/Metadata/metadata.xml.twig",
                    [
                        "metadata" => $this->buildMetadata()
                    ]
                )
            );
        } catch (\Exception $e) {
            throw new \RuntimeException("Could not render metadata template: " . $e->getMessage(), 0, $e);
        }
        
        $response->headers->set('Content-Type', 'xml');        
        
        return $response;
    }

    /**
     * @return Metadata
     */
    public function buildMetadata(){
        $metadata = new Metadata();

        $metadata->entityId = $this->hostedEntities->getEntityId();

        if($this->hostedEntities->hasIdentityProvider()){
            $idp = $this->hostedEntities->getIdentityProvider();

            $idpMetadata = new IdentityProviderMetadata();
            $idpMetadata->ssoUrl = $idp->getSsoUrl();
            $idpMetadata->slsUrl = $idp->getSlsUrl();

            $metadata->idp = $idpMetadata;

            $keys = KeyLoader::extractPublicKeys($idp);
            preg_match(Certificate::CERTIFICATE_PATTERN, $keys[0]->getCertificate(), $matches);
            $metadata->certificate = $matches[1];
        }

        return $metadata;
    }
}
