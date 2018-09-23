=======
History
=======
0.1.0a0 (2018-09-23)
--------------------

Bug Fixes
~~~~~~~~~

* Fix tests that break when run individually
* user - Use SQLAlchemy hybrid_property on User's columns
* endpoint - Use the table name for endpoint in add_resource
* auth - Validate only Claim type view_args against token

Features
~~~~~~~~

* Make default auth and database initialization optional
* app - Add add_resource method to Saraki and Blueprint
* endpoint

  - Make collection decorator aware of organization model classes
  - Add automatic API creation for organization resources
  - Add add_resource to automate API endpoints creation
* utility

  - Make @json support returns in the form (payload, headers)
  - Support global column exclusion from response payloads.
  - Use export_data method in export_from_sqla_object
  - Add current_org local proxy object
  - Add custom (Cerberus) validator
  - Add json decorator
  - Add export_from_sqla_object utility function
  - Add validation schema generator
* refactor - Require model_class only with unique rule in Validator
* auth

  - Include member privileges in access token
  - Add persistence for actions and resources
  - Add default scp claim value for organization owners
  - Add resource/action based authorization
  - Add authorization mechanism for org endpoints
  - Add initial authorization mechanism
  - Make iss claim optional by default
  - Add authentication
* role - Add member role management endpoints
* action - Add API to retrieve Action resources
* resource - Add API to retrieve Resource resources
* testing - Add a new module that implements test helpers
* plan - Add basic plans management
* member - Add endpoints to add and list members
* org - Add org account endpoints
* model - Add export_data method to Model class
* signup - Add signup endpoint

