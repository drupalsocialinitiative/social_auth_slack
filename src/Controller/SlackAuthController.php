<?php

namespace Drupal\social_auth_slack\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\social_api\Plugin\NetworkManager;
use Drupal\social_auth\SocialAuthDataHandler;
use Drupal\social_auth\SocialAuthUserManager;
use Drupal\social_auth_slack\SlackAuthManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Returns responses for Simple Slack Connect module routes.
 */
class SlackAuthController extends ControllerBase {

  /**
   * The network plugin manager.
   *
   * @var \Drupal\social_api\Plugin\NetworkManager
   */
  private $networkManager;

  /**
   * The user manager.
   *
   * @var \Drupal\social_auth\SocialAuthUserManager
   */
  private $userManager;

  /**
   * The slack authentication manager.
   *
   * @var \Drupal\social_auth_slack\SlackAuthManager
   */
  private $slackManager;

  /**
   * Used to access GET parameters.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  private $request;

  /**
   * The Social Auth Data Handler.
   *
   * @var \Drupal\social_auth\SocialAuthDataHandler
   */
  private $dataHandler;


  /**
   * The logger channel.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactoryInterface
   */
  protected $loggerFactory;

  /**
   * SlackAuthController constructor.
   *
   * @param \Drupal\social_api\Plugin\NetworkManager $network_manager
   *   Used to get an instance of social_auth_slack network plugin.
   * @param \Drupal\social_auth\SocialAuthUserManager $user_manager
   *   Manages user login/registration.
   * @param \Drupal\social_auth_slack\SlackAuthManager $slack_manager
   *   Used to manage authentication methods.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request
   *   Used to access GET parameters.
   * @param \Drupal\social_auth\SocialAuthDataHandler $data_handler
   *   SocialAuthDataHandler object.
   */
  public function __construct(NetworkManager $network_manager,
                              SocialAuthUserManager $user_manager,
                              SlackAuthManager $slack_manager,
                              RequestStack $request,
                              SocialAuthDataHandler $data_handler) {

    $this->networkManager = $network_manager;
    $this->userManager = $user_manager;
    $this->slackManager = $slack_manager;
    $this->request = $request;
    $this->dataHandler = $data_handler;
    // Sets the plugin id.
    $this->userManager->setPluginId('social_auth_slack');

    // Sets the session keys to nullify if user could not logged in.
    $this->userManager->setSessionKeysToNullify(['access_token', 'oauth2state']);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('plugin.network.manager'),
      $container->get('social_auth.user_manager'),
      $container->get('social_auth_slack.manager'),
      $container->get('request_stack'),
      $container->get('social_auth.data_handler'),
      $container->get('logger.factory')
    );
  }

  /**
   * Response for path 'user/login/slack'.
   *
   * Redirects the user to Slack for authentication.
   */
  public function redirectToSlack() {
    /* @var \AdamPaterson\OAuth2\Client\Provider\Slack false $slack */
    $slack = $this->networkManager->createInstance('social_auth_slack')->getSdk();

    // If slack client could not be obtained.
    if (!$slack) {
      drupal_set_message($this->t('Social Auth Slack not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // Slack service was returned, inject it to $slackManager.
    $this->slackManager->setClient($slack);

    // Generates the URL where the user will be redirected for authentication.
    $slack_login_url = $this->slackManager->getAuthorizationUrl();

    $state = $this->slackManager->getState();

    $this->dataHandler->set('oauth2state', $state);

    return new TrustedRedirectResponse($slack_login_url);
  }

  /**
   * Response for path 'user/login/slack/callback'.
   *
   * Slack returns the user here after user has authenticated in Slack.
   */
  public function callback() {
    // Checks if user cancel login via Slack.
    $error = $this->request->getCurrentRequest()->get('error');
    if ($error == 'access_denied') {
      drupal_set_message($this->t('You could not be authenticated.'), 'error');
      return $this->redirect('user.login');
    }

    /* @var \AdamPaterson\OAuth2\Client\Provider\Slack false $slack */
    $slack = $this->networkManager->createInstance('social_auth_slack')->getSdk();

    // If Slack client could not be obtained.
    if (!$slack) {
      drupal_set_message($this->t('Social Auth Slack not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    $state = $this->dataHandler->get('oauth2state');

    // Retrieves $_GET['state'].
    $retrievedState = $this->request->getCurrentRequest()->query->get('state');
    if (empty($retrievedState) || ($retrievedState !== $state)) {
      $this->userManager->nullifySessionKeys();
      drupal_set_message($this->t('Slack login failed. Unvalid OAuth2 State.'), 'error');
      return $this->redirect('user.login');
    }

    $this->slackManager->setClient($slack)->authenticate();

    // Saves access token to session.
    $this->dataHandler->set('access_token', $this->slackManager->getAccessToken());

    // Gets user's info from Slack API.
    /* @var \AdamPaterson\OAuth2\Client\Provider\SlackResourceOwner $profile */
    if (!$profile = $this->slackManager->getUserInfo()) {
      drupal_set_message($this->t('Slack login failed, could not load Slack profile. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // Gets (or not) extra initial data.
    $data = $this->userManager->checkIfUserExists($profile->getId()) ? NULL : $this->slackManager->getExtraDetails();

    // If user information could be retrieved.
    return $this->userManager->authenticateUser($profile->getName(), $profile->getEmail(), $profile->getId(), $this->slackManager->getAccessToken(), $profile->getImage192(), $data);

  }

}
