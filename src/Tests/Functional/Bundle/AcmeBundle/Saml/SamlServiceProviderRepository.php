<?php

namespace AdactiveSas\Saml2BridgeBundle\Tests\Functional\Bundle\AcmeBundle\Saml;


use AdactiveSas\Saml2BridgeBundle\Entity\ServiceProvider;
use AdactiveSas\Saml2BridgeBundle\Entity\ServiceProviderRepository;
use Symfony\Component\Security\Core\User\UserInterface;

class SamlServiceProviderRepository implements ServiceProviderRepository
{
    const SP_BASIC = "https://test.fake/metadata";
    const SP_NO_SIGNING = "https://test.other.fake/metadata";

    protected $spMap = [];

    public function __construct() {
        $this->spMap[static::SP_BASIC] = new ServiceProvider(
            [
                /**
                 * Returns the contents of an X509 pem certificate, without the '-----BEGIN CERTIFICATE-----' and
                 * '-----END CERTIFICATE-----'.
                 *
                 * @return null|string
                 */
                'certificateData' => 'MIIEJTCCAw2gAwIBAgIJANug+o++1X5IMA0GCSqGSIb3DQEBCwUAMIGoMQswCQYDVQQGEwJOTDEQMA4GA1UECAwHVXRyZWNodDEQMA4GA1UEBwwHVXRyZWNodDEVMBMGA1UECgwMU1VSRm5ldCBCLlYuMRMwEQYDVQQLDApTVVJGY29uZXh0MRwwGgYDVQQDDBNTVVJGbmV0IERldmVsb3BtZW50MSswKQYJKoZIhvcNAQkBFhxzdXJmY29uZXh0LWJlaGVlckBzdXJmbmV0Lm5sMB4XDTE0MTAyMDEyMzkxMVoXDTE0MTExOTEyMzkxMVowgagxCzAJBgNVBAYTAk5MMRAwDgYDVQQIDAdVdHJlY2h0MRAwDgYDVQQHDAdVdHJlY2h0MRUwEwYDVQQKDAxTVVJGbmV0IEIuVi4xEzARBgNVBAsMClNVUkZjb25leHQxHDAaBgNVBAMME1NVUkZuZXQgRGV2ZWxvcG1lbnQxKzApBgkqhkiG9w0BCQEWHHN1cmZjb25leHQtYmVoZWVyQHN1cmZuZXQubmwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDXuSSBeNJY3d4p060oNRSuAER5nLWT6AIVbv3XrXhcgSwc9m2b8u3ksp14pi8FbaNHAYW3MjlKgnLlopYIylzKD/6Ut/clEx67aO9Hpqsc0HmIP0It6q2bf5yUZ71E4CN2HtQceO5DsEYpe5M7D5i64kS2A7e2NYWVdA5Z01DqUpQGRBc+uMzOwyif6StBiMiLrZH3n2r5q5aVaXU4Vy5EE4VShv3Mp91sgXJj/v155fv0wShgl681v8yf2u2ZMb7NKnQRA4zM2Ng2EUAyy6PQ+Jbn+rALSm1YgiJdVuSlTLhvgwbiHGO2XgBi7bTHhlqSrJFK3Gs4zwIsop/XqQRBAgMBAAGjUDBOMB0GA1UdDgQWBBQCJmcoa/F7aM3jIFN7Bd4uzWRgzjAfBgNVHSMEGDAWgBQCJmcoa/F7aM3jIFN7Bd4uzWRgzjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBd80GpWKjp1J+Dgp0blVAox1s/WPWQlex9xrx1GEYbc5elp3svS+S82s7dFm2llHrrNOBt1HZVC+TdW4f+MR1xq8O5lOYjDRsosxZc/u9jVsYWYc3M9bQAx8VyJ8VGpcAK+fLqRNabYlqTnj/t9bzX8fS90sp8JsALV4g84Aj0G8RpYJokw+pJUmOpuxsZN5U84MmLPnVfmrnuCVh/HkiLNV2c8Pk8LSomg6q1M1dQUTsz/HVxcOhHLj/owwh3IzXf/KXV/E8vSYW8o4WWCAnruYOWdJMI4Z8NG1Mfv7zvb7U3FL1C/KLV04DqzALXGj+LVmxtDvuxqC042apoIDQV',

                /**
                 * @return null|string
                 */
                "entityId" => static::SP_BASIC,

                "assertionConsumerUrl" => "https://test.fake/saml/acs",
                "assertionConsumerBinding" => \SAML2_Const::BINDING_HTTP_REDIRECT,
                "supportSingleLogout" => true,
                "singleLogoutUrl" => "https://test.fake/saml/sls",
                "singleLogoutBinding" => \SAML2_Const::BINDING_HTTP_REDIRECT,
                "nameIdValue" => "moroine",
                "attributes" => [
                    'email' => function (UserInterface $user) {
                        return "moroine.bentefrit@gmail.com";
                    },
                ],
            ]
        );
        $this->spMap[static::SP_NO_SIGNING] = new ServiceProvider(
            [
                /**
                 * @return null|string
                 */
                "entityId" => static::SP_NO_SIGNING,

                "assertionConsumerUrl" => "https://test.other.fake/saml/acs",
                "assertionConsumerBinding" => \SAML2_Const::BINDING_HTTP_REDIRECT,
                "singleLogoutUrl" => "https://test.other.fake/saml/sls",
                "singleLogoutBinding" => \SAML2_Const::BINDING_HTTP_REDIRECT,
                "wantSignedAuthnRequest" => false,
                "wantSignedAuthnResponse" => false,
                "wantSignedAssertions" => false,
                "supportSingleLogout" => true,
                "wantSignedLogoutResponse" => false,
                "wantSignedLogoutRequest" => false,
                "nameIdValue" => "moroine",
                "attributes" => [
                    'email' => function (UserInterface $user) {
                        return "moroine.bentefrit@gmail.com";
                    },
                ],
            ]
        );
    }

    /**
     * @param string $entityId
     * @return ServiceProvider
     */
    public function getServiceProvider($entityId)
    {
        return $this->hasServiceProvider($entityId) ? $this->spMap[$entityId] : null;
    }

    /**
     * @param string $entityId
     * @return bool
     */
    public function hasServiceProvider($entityId)
    {
        return array_key_exists($entityId, $this->spMap);
    }
}
