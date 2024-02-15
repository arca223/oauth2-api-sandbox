<?php

namespace App\Controller;

use League\OAuth2\Client\Provider\GenericProvider;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

class ApiController extends AbstractController
{


    #[Route('/api', name: 'app_api')]
    public function index(): JsonResponse
    {

        $provider = new GenericProvider([
            'clientId' => $_ENV['CLIENT_ID_HYDRA'],    // L'ID client attribué par le fournisseur
            'clientSecret' => $_ENV['CLIENT_SECRET_HYDRA'], // Le secret client attribué par le fournisseur
            'redirectUri' => 'http://127.0.0.1:8000/api',
            'urlAuthorize'            => 'https://kind-wozniak-9dkzywk2t8.projects.oryapis.com/oauth2/auth',
            'urlAccessToken'          => 'https://kind-wozniak-9dkzywk2t8.projects.oryapis.com/oauth2/token',
            'urlResourceOwnerDetails' => 'https://kind-wozniak-9dkzywk2t8.projects.oryapis.com/userinfo'
        ]);

        if (isset($_GET['code'])) {
            try {
                //dd($provider->getAuthorizationUrl());
                $accessToken = $provider->getAccessToken('authorization_code', [
                    'code' => $_GET['code'],
                ]);

                $resourceOwner = $provider->getResourceOwner($accessToken);

                return $this->json([
                    'accessToken' => $accessToken,
                    'resourceOwner' => $resourceOwner->toArray(),
                ]);
                // Vous pouvez maintenant utiliser $accessToken pour accéder aux ressources protégées
            } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
                return $this->json([
                    'error' => $e->getCode(),
                    'message' => $e->getMessage()
                ]);
            }
        } else {
            $authorizationUrl = $provider->getAuthorizationUrl();
            header('Location: ' . $authorizationUrl);
            exit;
        }

        return $this->json([
            'message' => 'nothing here'
        ]);
    }
}
