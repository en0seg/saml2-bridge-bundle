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

namespace AdactiveSas\Saml2BridgeBundle\SAML2\Binding;

use AdactiveSas\Saml2BridgeBundle\Exception\BadRequestHttpException;
use AdactiveSas\Saml2BridgeBundle\Exception\LogicException;
use AdactiveSas\Saml2BridgeBundle\Form\SAML2ResponseForm;
use AdactiveSas\Saml2BridgeBundle\SAML2\Binding\Exception\UnsupportedBindingException;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\StatusResponse;
use Symfony\Component\Form\FormFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Twig\Environment;
use Twig\Error\LoaderError;
use Twig\Error\RuntimeError;
use Twig\Error\SyntaxError;

class HttpPostBinding extends AbstractHttpBinding implements HttpBindingInterface
{
    /**
     * @var FormFactoryInterface
     */
    protected $formFactory;

    /**
     * @var Environment
     */
    protected $twig;

    /**
     * HttpPostBinding constructor.
     * @param FormFactoryInterface $formFactory
     * @param Environment $twig
     */
    public function __construct(FormFactoryInterface $formFactory, Environment $twig)
    {
        $this->formFactory = $formFactory;
        $this->twig = $twig;
    }

    /**
     * @param StatusResponse $response
     * @return Response
     * @throws \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     * @throws \RuntimeException
     */
    public function getSignedResponse(StatusResponse $response): Response
    {
        $form = $this->getSignedResponseForm($response);

        $response = new Response();

        try {
            $response->setContent(
                $this->twig->render(
                    "@AdactiveSasSaml2Bridge/Binding/post.html.twig",
                    [
                        "form" => $form->createView(),
                    ]
                )
            );
        } catch (LoaderError | RuntimeError | SyntaxError $e) {
            throw new \RuntimeException(sprintf(
                'Could not render the response form: %s',
                $e->getMessage()
            ), 0, $e);
        }

        return $response;
    }

    /**
     * @param StatusResponse $response
     * @return Response
     * @throws \RuntimeException
     * @throws \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    public function getUnsignedResponse(StatusResponse $response)
    {
        $form = $this->getUnsignedResponseForm($response);

        $response = new Response();

        try {
            $response->setContent(
                $this->twig->render(
                    "@AdactiveSasSaml2Bridge/Binding/post.html.twig",
                    [
                    "form" => $form->createView(),
                    ]
                )
            );
        } catch (LoaderError | RuntimeError | SyntaxError $e) {
            throw new \RuntimeException(sprintf(
                'Could not render the response form: %s',
                $e->getMessage()
            ), 0, $e);
        }
    }

    /**
     * @param Request $request
     * @return ReceivedData
     * @throws \AdactiveSas\Saml2BridgeBundle\SAML2\Binding\Exception\InvalidReceivedMessageQueryStringException
     * @throws \AdactiveSas\Saml2BridgeBundle\Exception\BadRequestHttpException
     */
    protected function getReceivedData(Request $request)
    {
        if (!$request->isMethod(Request::METHOD_POST)) {
            throw new BadRequestHttpException(sprintf(
                'Could not receive Message from HTTP Request: expected a POST method, got %s',
                $request->getMethod()
            ));
        }

        $requestParams = $request->request->all();

        return ReceivedData::fromReceivedProviderData($requestParams);
    }

    /**
     * @param StatusResponse $response
     * @return \Symfony\Component\Form\FormInterface
     * @throws \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    protected function getSignedResponseForm(StatusResponse $response)
    {
        return $this->getResponseForm($response, true);
    }

    /**
     * @param StatusResponse $response
     * @return \Symfony\Component\Form\FormInterface
     * @throws \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    protected function getUnsignedResponseForm(StatusResponse $response)
    {
        return $this->getResponseForm($response, false);
    }

    /**
     * @param StatusResponse $response
     * @param bool $isSign
     * @return \Symfony\Component\Form\FormInterface
     * @throws \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    protected function getResponseForm(StatusResponse $response, bool $isSign)
    {
        if ($response->getDestination() === null) {
            throw new LogicException('Invalid destination');
        }

        $xmlDom = $isSign ? $response->toSignedXML() : $response->toUnsignedXML();

        $data = [
            'SAMLResponse' => base64_encode($xmlDom->ownerDocument->saveXML()),
        ];

        $hasRelayState = !empty($response->getRelayState());
        if ($hasRelayState) {
            $data["RelayState"] = $response->getRelayState();
        }

        return $this->formFactory->createNamed(
            "",
            SAML2ResponseForm::class,
            $data,
            [
            "has_relay_state" => $hasRelayState,
            "destination" => $response->getDestination(),
            ]
        );
    }

    /**
     * @param \SAML2\Request $request
     * @return Response
     * @throws \InvalidArgumentException
     * @throws \AdactiveSas\Saml2BridgeBundle\Exception\LogicException
     */
    public function getSignedRequest(\SAML2\Request $request): Response
    {

        //throw new UnsupportedBindingException("Unsupported binding: build POST Request is not supported at the moment");

        $form = $this->getSignedRequestForm($request);

        $response = new Response();
        try {
            $response->setContent(
                $this->twig->render(
                    "@AdactiveSasSaml2Bridge/Binding/post.html.twig",
                    [
                        "form" => $form->createView(),
                    ]
                )
            );
        } catch (LoaderError | RuntimeError | SyntaxError $e) {
            throw new \RuntimeException(sprintf(
                'Could not render the request form: %s',
                $e->getMessage()
            ), 0, $e);
        }
    }

    /**
     * @param \SAML2\Request $request
     * @return Response
     * @throws \AdactiveSas\Saml2BridgeBundle\SAML2\Binding\Exception\UnsupportedBindingException
     */
    public function getUnsignedRequest(\SAML2\Request $request)
    {
        // throw new UnsupportedBindingException("Unsupported binding: unsigned POST Request is not supported at the moment");

        $form = $this->getUnsignedRequestForm($request);

        $response = new Response();
        try {
            $response->setContent(
                $this->twig->render(
                    "@AdactiveSasSaml2Bridge/Binding/post.html.twig",
                    [
                        "form" => $form->createView(),
                    ]
                )
            );
        } catch (LoaderError | RuntimeError | SyntaxError $e) {
            throw new \RuntimeException(sprintf(
                'Could not render the request form: %s',
                $e->getMessage()
            ), 0, $e);
        }
    }

    /**
     * @param \SAML2\Request $response
     * @return \Symfony\Component\Form\FormInterface
     * @throws \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    protected function getSignedRequestForm(\SAML2\Request $response)
    {
        return $this->getRequestForm($response, true);
    }

    /**
     * @param \SAML2\Request $request
     * @return \Symfony\Component\Form\FormInterface
     * @throws \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    protected function getUnsignedRequestForm(\SAML2\Request $request)
    {
        return $this->getRequestForm($request, false);
    }

    /**
     * @param \SAML2\Request $request
     * @param bool $isSign
     * @return \Symfony\Component\Form\FormInterface
     * @throws \Symfony\Component\OptionsResolver\Exception\InvalidOptionsException
     */
    protected function getRequestForm(\SAML2\Request $request, bool $isSign)
    {
        if ($request->getDestination() === null) {
            throw new LogicException('Invalid destination');
        }

        $xmlDom = $isSign ? $request->toSignedXML() : $request->toUnsignedXML();

        $data = [
            'SAMLResponse' => base64_encode($xmlDom->ownerDocument->saveXML()),
        ];

        $hasRelayState = !empty($request->getRelayState());
        if ($hasRelayState) {
            $data["RelayState"] = $request->getRelayState();
        }

        return $this->formFactory->createNamed(
            "",
            SAML2ResponseForm::class,
            $data,
            [
                "has_relay_state" => $hasRelayState,
                "destination" => $request->getDestination(),
            ]
        );
    }
}
