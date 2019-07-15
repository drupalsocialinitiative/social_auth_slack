<?php

namespace Drupal\social_auth_slack\Plugin\Network;

use AdamPaterson\OAuth2\Client\Provider\Slack;
use Drupal\social_api\SocialApiException;
use Drupal\social_auth\Plugin\Network\NetworkBase;
use Drupal\social_auth_slack\Settings\SlackAuthSettings;

/**
 * Defines a Network Plugin for Social Auth Slack.
 *
 * @package Drupal\social_auth_slack\Plugin\Network
 *
 * @Network(
 *   id = "social_auth_slack",
 *   social_network = "Slack",
 *   type = "social_auth",
 *   handlers = {
 *     "settings": {
 *       "class": "\Drupal\social_auth_slack\Settings\SlackAuthSettings",
 *       "config_id": "social_auth_slack.settings"
 *     }
 *   }
 * )
 */
class SlackAuth extends NetworkBase implements SlackAuthInterface {

  /**
   * Sets the underlying SDK library.
   *
   * @return \AdamPaterson\OAuth2\Client\Provider\Slack
   *   The initialized 3rd party library instance.
   *
   * @throws \Drupal\social_api\SocialApiException
   *   If the SDK library does not exist.
   */
  protected function initSdk() {

    $class_name = 'AdamPaterson\OAuth2\Client\Provider\Slack';
    if (!class_exists($class_name)) {
      throw new SocialApiException(sprintf('The Slack library for PHP League OAuth2 not found. Class: %s.', $class_name));
    }

    /** @var \Drupal\social_auth_slack\Settings\SlackAuthSettings $settings */
    $settings = $this->settings;
    if ($this->validateConfig($settings)) {
      // All these settings are mandatory.
      $league_settings = [
        'clientId' => $settings->getClientId(),
        'clientSecret' => $settings->getClientSecret(),
        'redirectUri' => $this->requestContext->getCompleteBaseUrl() . '/user/login/slack/callback',
      ];

      // Proxy configuration data for outward proxy.
      $proxyUrl = $this->siteSettings->get('http_client_config')['proxy']['http'];
      if ($proxyUrl) {
        $league_settings['proxy'] = $proxyUrl;
      }

      return new Slack($league_settings);
    }

    return FALSE;
  }

  /**
   * Checks that module is configured.
   *
   * @param \Drupal\social_auth_slack\Settings\SlackAuthSettings $settings
   *   The Slack auth settings.
   *
   * @return bool
   *   True if module is configured correctly.
   *   False otherwise.
   */
  protected function validateConfig(SlackAuthSettings $settings) {
    $client_id = $settings->getClientId();
    $client_secret = $settings->getClientSecret();
    if (!$client_id || !$client_secret) {
      $this->loggerFactory
        ->get('social_auth_slack')
        ->error('Define Client ID and Client Secret on module settings.');

      return FALSE;
    }

    return TRUE;
  }

}
