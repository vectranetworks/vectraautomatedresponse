import json
import re
import time
import warnings
import logging
import keyring
import requests
import vat.vectra as vectra
from requests.auth import HTTPBasicAuth

warnings.filterwarnings("always", ".*", PendingDeprecationWarning)


class HTTPException(Exception):
    def __init__(self, response):
        """
        Custom exception class to report possible API errors
        The body is constructed by extracting the API error code from the requests.Response object
        """
        try:
            r = response.json()
            if "detail" in r:
                detail = r["detail"]
            elif "errors" in r:
                detail = r["errors"][0]["title"]
            elif "_meta" in r:
                detail = r["_meta"]["message"]
            else:
                detail = response.content
        except Exception:
            detail = response.content
        body = f"Status code: {str(response.status_code)} - {detail}"
        super().__init__(body)


class HTTPUnauthorizedException(HTTPException):
    """Specific Exception"""


class HTTPTooManyRequestsException(HTTPException):
    """Specific Exception"""


def request_error_handler(func):
    def request_handler(self, *args, **kwargs):
        response = func(self, *args, **kwargs)
        if response.status_code in [200, 201, 204]:
            return response
        elif response.status_code == 401:
            raise HTTPUnauthorizedException(response)
        elif response.status_code == 429:
            raise HTTPTooManyRequestsException(response)
        else:
            raise HTTPException(response)

    return request_handler

def renew_access_token(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except HTTPUnauthorizedException as e:
            # To calculate token expiration we take 10s margin
            if not self.refresh_token or (
                self.access_token_validity - time.time() > 10.0
                and self.refresh_token_validity - time.time() > 10.0
            ):
                raise
            elif self.refresh_token_validity - time.time() < 10.0:
                self.logger.debug('Refresh token expired, re-doing OAuth')
                self._get_oauth_token()
                # Once the token is refreshed, we can retry the operation.
                return func(self, *args, **kwargs)
            else:
                self.logger.debug('Access token expired, refreshing with refresh token')
                self._refresh_oauth_token()  # This resets the validity, so we don't retry indefinitely
                # Once the token is refreshed, we can retry the operation.
                return func(self, *args, **kwargs)
        except HTTPTooManyRequestsException:
            time.sleep(1)
            return func(self, *args, **kwargs)

    return wrapper


def aws_cognito_timeout(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except HTTPTooManyRequestsException:
            time.sleep(15)
            return func(self, *args, **kwargs)

    return wrapper


def deprecation(message):
    warnings.warn(message, PendingDeprecationWarning)


def param_deprecation(key):
    message = f"{key} will be deprecated with Vectra API which will be announced in an upcoming release"
    warnings.warn(message, PendingDeprecationWarning)




class VectraSaaSClient(vectra.ClientV2_latest):
    def __init__(
        self,
        url=None,
        client_id=None,
        secret_key=None,
        verify=False,
    ):
        """
        Initialize Vectra Saas client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - required
        :param secret_key: API Secret Key for authentication - required
        :param verify: Verify SSL (default: False) - optional
        """
        url = VectraSaaSClient._remove_trailing_slashes(url)
        self.base_url = url
        self.logger = logging.getLogger()
        self.version = 3
        self.url = f"{url}/api/v{self.version}"
        self.verify = verify
        self.client_id = client_id
        self.secret_key = secret_key
        self.access_token = VectraSaaSClient._get_keyring_password(url, "rux_access_token")
        self.refresh_token = VectraSaaSClient._get_keyring_password(url,"rux_refresh_token")
        # Retrieve expiration times and cast back to float
        self.access_token_validity = float(VectraSaaSClient._get_keyring_password(url,"rux_access_token_validity")) if VectraSaaSClient._get_keyring_password(url,"rux_access_token_validity") else None
        self.refresh_token_validity = float(VectraSaaSClient._get_keyring_password(url,"rux_refresh_token_validity")) if VectraSaaSClient._get_keyring_password(url,"rux_refresh_token_validity") else None
  
        # Setup authorization in headers
        self.headers = {
            "Authorization": self.access_token,
            "Content-Type": "application/json",
            "Cache-Control": "no-cache",
        }

        if client_id and secret_key:
            self.auth = (client_id, secret_key)
        else:
            raise RuntimeError(
                "API Client ID and Secret Key are required for authentication."
            )

    @staticmethod
    def _get_keyring_password(system, username):
        """
        Wrapper around keyring, since it can return either None or '' on an unset keyring entry,
        depending whether this entry was previously used or not
        """
        response = keyring.get_password(system, username)
        if response is None or response == '':
            return None
        else:
            return response

    @staticmethod
    def _remove_trailing_slashes(url):
        if ":/" not in url:
            url = "https://" + url
        else:
            url = re.sub("^.*://?", "https://", url)
        url = url[:-1] if url.endswith("/") else url
        return url

    @aws_cognito_timeout
    @request_error_handler
    def _get_oauth_token_request(self):
        data = {"grant_type": "client_credentials"}
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        url = f"{self.base_url}/oauth2/token"
        return requests.post(
            url,
            headers=headers,
            data=data,
            auth=HTTPBasicAuth(self.client_id, self.secret_key),
            verify=self.verify,
        )

    def _get_oauth_token(self):
        # Get the OAuth2 token
        r_dict = self._get_oauth_token_request().json()
        self.access_token = r_dict.get("access_token")
        self.refresh_token = r_dict.get("refresh_token")
        self.access_token_validity = time.time() + r_dict.get("expires_in")
        self.refresh_token_validity = time.time() + r_dict.get("refresh_expires_in")
        self.headers["Authorization"] = "Bearer " + self.access_token
        # Save in Keyring
        self.logger.debug('Saving to keyring')
        keyring.set_password(self.base_url,"rux_access_token", self.access_token)
        keyring.set_password(self.base_url,"rux_refresh_token", self.refresh_token)
        keyring.set_password(self.base_url,"rux_access_token_validity", str(self.access_token_validity)) #keyring only stores Strings
        keyring.set_password(self.base_url,"rux_refresh_token_validity", str(self.refresh_token_validity))


    @aws_cognito_timeout
    @request_error_handler
    def _refresh_oauth_token_request(self):
        data = {"grant_type": "refresh_token", "refresh_token": self.refresh_token}
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        url = f"{self.base_url}/oauth2/token"
        return requests.post(url, headers=headers, data=data, verify=self.verify)

    def _refresh_oauth_token(self):
        r_dict = self._refresh_oauth_token_request().json()
        token = r_dict.get("access_token")
        self.access_token_validity = time.time() + r_dict.get("expires_in")
        # Saving updated value to keyring
        keyring.set_password(self.base_url,"rux_access_token_validity", str(self.access_token_validity)) #keyring only stores Strings
        self.headers["Authorization"] = "Bearer " + token

    @renew_access_token
    @request_error_handler
    def _request(self, method, url, **kwargs):
        """
        Do a get request on the provided URL
        This is used by paginated endpoints
        :rtype: requests.Response
        """
        if method not in ["get", "patch", "put", "post", "delete"]:
            raise ValueError("Invalid requests method provided")

        if not self.access_token:
            # Get the OAuth2 token
            self._get_oauth_token()

        if "headers" in kwargs.keys():
            headers = kwargs.pop("headers")
        else:
            headers = self.headers
        return requests.request(
            method=method, url=url, headers=headers, verify=self.verify, **kwargs
        )

    @staticmethod
    def _generate_account_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "all",
            "c_score",
            "c_score_gte",
            "fields",
            "id",
            "max_id",
            "min_id",
            "name",
            "note_modified_timestamp_gte",
            "ordering",
            "page",
            "page_size",
            "privilege_category",
            "privilege_level",
            "privilege_level_gte",
            "state",
            "t_score",
            "t_score_gte",
            "tags",
        ]
        deprecated_keys = []
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    @staticmethod
    def _generate_assignment_params(args):
        """
        Generate query parameters for assignment queries based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        :param accounts: filter by accounts ([int])
        :param assignees: filter by assignees (int)
        :param created_after: filter by created after timestamp
        :param resolution: filter by resolution (int)
        :param resolved: filters by resolved status (bool)
        """
        params = {}
        valid_keys = [
            "accounts",
            "assignees",
            "created_after",
            "resolution",
            "resolved",
        ]

        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    if isinstance(v, list):
                        # Backend needs list parameters as a comma-separated list
                        str_values = [str(int) for int in v]
                        params[k] = ",".join(str_values)
                    else:
                        params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid assignment query parameter"
                )
        return params

    @staticmethod
    def _generate_resolution_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "accounts",
            "assignees",
            "resolution",
            "resolved",
            "created_after",
        ]
        deprecated_keys = []
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    @staticmethod
    def _generate_account_event_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ["from", "limit"]
        deprecated_keys = []
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    @staticmethod
    def _generate_audit_log_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "event_action",
            "event_object",
            "event_timestamp_gte",
            "event_timestamp_lte",
            "from",
            "limit",
            "user_id",
        ]
        deprecated_keys = []
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    def get_detection_notes(self, detection_id=None):
        """
        Get detection notes
        :param detection_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete detection body, we alter the response content
        """
        if not detection_id:
            raise ValueError("Must provide detection_id.")
        detection = self._request(
            method="get", url=f"{self.url}/detections/{detection_id}/notes"
        )
        if detection.status_code == 200:
            json_dict = {
                "status": "success",
                "detection_id": str(detection_id),
                "notes": detection.json()["notes"],
            }
            detection._content = json.dumps(json_dict).encode("utf-8")
        return detection

    def get_detection_note_by_id(self, detection_id=None, note_id=None):
        """
        Get detection notes
        :param detection_id:
        :param note_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete detection body, we alter the response content
        """
        if not detection_id:
            raise ValueError("Must provide detection_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        detection = self._request(
            method="get", url=f"{self.url}/detections/{detection_id}/notes/{note_id}"
        )
        return detection

    def set_detection_note(self, detection_id=None, note=""):
        """
        Set detection note
        :param detection_id: - required
        :param note: content of the note to set - required
        """
        if not detection_id:
            raise ValueError("Must provide detection_id.")

        if isinstance(note, str) and note != "":
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str and cannot be empty.")

        return self._request(
            method="post",
            url=f"{self.url}/detections/{detection_id}/notes",
            json=payload,
        )

    def update_detection_note(
        self, detection_id=None, note_id=None, note="", append=False
    ):
        """
        Set detection note
        :param detection_id: - required
        :param note: content of the note to set - required
        :param append: overwrites existing note if set to False, appends if set to True
        """
        if not detection_id:
            raise ValueError("Must provide detection_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        if append and isinstance(note, str):
            current_note = self.get_detection_note_by_id(
                detection_id=detection_id, note_id=note_id
            ).json()["note"]
            if current_note:
                if len(note) > 0:
                    payload = {"note": f"{current_note}\n{note}"}
                else:
                    payload = {"note": current_note}
            else:
                payload = {"note": note}
        elif isinstance(note, str) and note != "":
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str and cannot be empty.")

        return self._request(
            method="patch",
            url=f"{self.url}/detections/{detection_id}/notes/{note_id}",
            json=payload,
        )

    def delete_detection_note(self, detection_id=None, note_id=None):
        """
        Set detection note
        :param detection_id: - required
        :param note_id - required
        """
        if not detection_id:
            raise ValueError("Must provide detection_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        return self._request(
            method="delete", url=f"{self.url}/detections/{detection_id}/notes/{note_id}"
        )

    def get_account_tags(self, account_id=None):
        """
        Get Account tags
        :param account_id: ID of the account for which to retrieve the tags - required
        """
        if not account_id:
            raise ValueError("Must provide account_id.")
        return self._request(
            method="get", url=f"{self.url}/tagging/account/{account_id}"
        )

    def set_account_tags(self, account_id=None, tags=[], append=False):
        """
        Set account tags
        :param account_id: ID of the account for which to set the tags - required
        :param tags: list of tags to add to account
        :param append: overwrites existing list if set to False (default), appends to existing tags if set to True
        Set to empty list to clear tags
        """
        if not account_id:
            raise ValueError("Must provide account_id.")
        if append and isinstance(tags, list):
            current_list = self.get_account_tags(account_id=account_id).json()["tags"]
            payload = {"tags": current_list + tags}
        elif isinstance(tags, list):
            payload = {"tags": tags}
        else:
            raise TypeError("tags must be of type list")

        return self._request(
            method="patch", url=f"{self.url}/tagging/account/{account_id}", json=payload
        )

    def get_account_notes(self, account_id=None):
        """
        Get account notes
        :param account_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete account body, we alter the response content
        """
        if not account_id:
            raise ValueError("Must provide account_id.")
        account = self._request(
            method="get", url=f"{self.url}/accounts/{account_id}/notes"
        )
        if account.status_code == 200:
            # account_note = account.json()['note']
            # API endpoint return HTML escaped characters
            # account_note = html.unescape(account_note) if account_note else ''
            json_dict = {
                "status": "success",
                "account_id": str(account_id),
                "notes": account.json()["notes"],
            }
            account._content = json.dumps(json_dict).encode("utf-8")
        return account

    def get_account_note_by_id(self, account_id=None, note_id=None):
        """
        Get account notes
        :param account_id:
        :param note_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete account body, we alter the response content
        """
        if not account_id:
            raise ValueError("Must provide account_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        account = self._request(
            method="get", url=f"{self.url}/accounts/{account_id}/notes/{note_id}"
        )
        return account

    def set_account_note(self, account_id=None, note=""):
        """
        Set account note
        :param account_id:
        :param note: content of the note to set
        """
        if not account_id:
            raise ValueError("Must provide account_id.")

        if isinstance(note, str):
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str")

        return self._request(
            method="post", url=f"{self.url}/accounts/{account_id}/notes", json=payload
        )

    def update_account_note(self, account_id=None, note_id=None, note="", append=False):
        """
        Set account note
        :param account_id:
        :param note: content of the note to set
        :param append: overwrites existing note if set to False, appends if set to True
        Set to empty note string to clear account note
        """
        if not account_id:
            raise ValueError("Must provide account_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        if append and isinstance(note, str):
            current_note = self.get_account_note_by_id(
                account_id=account_id, note_id=note_id
            ).json()["note"]
            if current_note:
                if len(note) > 0:
                    payload = {"note": f"{current_note}\n{note}"}
                else:
                    payload = {"note": current_note}
            else:
                payload = {"note": note}
        elif isinstance(note, str):
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str")

        return self._request(
            method="patch",
            url=f"{self.url}/accounts/{account_id}/notes/{note_id}",
            json=payload,
        )

    def delete_account_note(self, account_id=None, note_id=None):
        """
        Set account note
        :param account_id:
        :param note: content of the note to set
        """
        if not account_id:
            raise ValueError("Must provide account_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        return self._request(
            method="delete", url=f"{self.url}/accounts/{account_id}/notes/{note_id}"
        )

    def get_all_assignments(self, **kwargs):
        """
        Generator to retrieve all assignments - all parameters are optional
        :param accounts: filter by accounts ([int])
        :param assignees: filter by assignees (int)
        :param created_after: filter by created after timestamp
        :param resolution: filter by resolution (int)
        :param resolved: filters by resolved status (bool)
        """
        resp = self._request(
            method="get",
            url=f"{self.url}/assignments",
            params=self._generate_assignment_params(kwargs),
        )
        yield resp
        while resp.json()["next"]:
            resp = self._request(method="get", url=resp.json()["next"])
            yield resp

    def create_account_assignment(self, assign_account_id, assign_to_user_id):
        """
        Create new assignment
        :param assign_account_id: ID of the account to assign
        :param assign_to_user_id: ID of the assignee
        """
        payload = {
            "assign_account_id": assign_account_id,
            "assign_to_user_id": assign_to_user_id,
        }
        return self._request(method="post", url=f"{self.url}/assignments", json=payload)

    def update_assignment(self, assignment_id=None, assign_to_user_id=None):
        """
        Update an existing assignment
        :param assignment_id: ID of the assignment to update
        :param assign_to_user_id: ID of the assignee
        """
        if not assignment_id:
            raise ValueError("Must provide assignment_id.")
        if not assign_to_user_id:
            raise ValueError("Must provide user_id for assignment.")
        payload = {"assign_to_user_id": assign_to_user_id}
        return self._request(
            method="put", url=f"{self.url}/assignments/{assignment_id}", json=payload
        )

    def delete_assignment(self, assignment_id):
        """
        Delete assignment
        :param assignment_id: assignment ID
        """
        if not assignment_id:
            raise ValueError("Must provide assignment_id.")
        return self._request(
            method="delete", url=f"{self.url}/assignments/{assignment_id}"
        )

    def set_assignment_resolved(
        self,
        assignment_id=None,
        detection_ids=[],
        outcome=None,
        note="",
        mark_as_fixed=False,
        triage_as=None,
    ):
        """
        Set an assignment as resolved
        :param outcome: integer value corresponding to the following:
            1: benign_true_positive
            2: malicious_true_positive
            3: false_positive
        :param note: Note to add to fixed/triaged detections
        :param triage_as: One-time triage detection(s) and rename as (str).
        :param mark_as_fixed: mark the detection(s) as fixed (bool). Custom triage_as and mark_as_fixed are mutually exclusive.
        :param detection_ids: list of detection IDs to fix/triage
        """
        if not triage_as and not mark_as_fixed:
            raise ValueError("Either triage_as or mark_as_fixed are requited")

        payload = {
            "outcome": outcome,
            "note": note,
            "mark_as_fixed": mark_as_fixed,
            "triage_as": triage_as,
            "detection_ids": detection_ids,
        }
        return self._request(
            method="put",
            url=f"{self.url}/assignments/{assignment_id}/resolve",
            json=payload,
        )

    def get_all_assignment_outcomes(self):
        """
        Get all outcomes
        """
        resp = self._request(method="get", url=f"{self.url}/assignment_outcomes")
        yield resp
        while resp.json()["next"]:
            resp = self._request(method="get", url=resp.json()["next"])
            yield resp

    def get_assignment_outcome_by_id(self, outcome_id=None):
        """
        Describe an existing Assignment Outcome
        """
        if not outcome_id:
            raise ValueError("Must provide outcome_id.")
        return self._request(
            method="get", url=f"{self.url}/assignment_outcomes/{outcome_id}"
        )

    def create_assignment_outcome(self, title="", category=""):
        """
        Create a new custom Assignment Outcome
        :param tile: title of the new Assignment Outcome to create.
        :param category: one of benign_true_positive, malicious_true_positive or false_positive
        """
        if category not in [
            "benign_true_positive",
            "malicious_true_positive",
            "false_positive",
        ]:
            raise ValueError("Invalid category provided")

        if title == "":
            raise ValueError("Title cannot be empty.")
        payload = {"title": title, "category": category}
        return self._request(
            method="post", url=f"{self.url}/assignment_outcomes", json=payload
        )

    def update_assignment_outcome(self, outcome_id=None, title="", category=""):
        """
        Update an existing custom Assignment Outcome
        :param outcome_id:
        :param tile: title of the new Assignment Outcome to create.
        :param category: one of benign_true_positive, malicious_true_positive or false_positive
        """
        if category not in [
            "benign_true_positive",
            "malicious_true_positive",
            "false_positive",
        ]:
            raise ValueError("Invalid category provided")

        if title == "":
            raise ValueError("Title cannot be empty.")

        payload = {"title": title, "category": category}
        return self._request(
            method="put",
            url=f"{self.url}/assignment_outcomes/{outcome_id}",
            json=payload,
        )

    def delete_assignment_outcome(self, outcome_id=None):
        """
        Delete an existing custom Assignment Outcome
        :param outcome_id: ID of the Assignment Outcome to delete
        """
        if not outcome_id:
            raise ValueError("Must provide outcome_id.")
        return self._request(
            method="delete", url=f"{self.url}/assignment_outcomes/{outcome_id}"
        )

    def get_account_scoring(self, **kwargs):
        """
        Get account scoring
        :param from:
        :param limit:
        """
        return self._request(
            method="get",
            url=f"{self.url}/events/account_scoring",
            params=self._generate_account_event_params(kwargs),
        )

    def get_account_detection(self, **kwargs):
        """
        Get account detection
        :param from:
        :param limit:
        """
        return self._request(
            method="get",
            url=f"{self.url}/events/account_detection",
            params=self._generate_account_event_params(kwargs),
        )

    def get_audits(self, **kwargs):
        """
        Requires certain privs - Handle the error
        Get audit events
        :param event_timestamp_gte:
        :param event_timestamp_lte:
        :param from:
        :param user_id:
        :param event_object:
        :param event_action:
        :param limit:
        """
        return self._request(
            method="get",
            url=f"{self.url}/events/audits",
            params=self._generate_audit_log_params(kwargs),
        )


class VectraSaaSClientV3_1(VectraSaaSClient):
    def __init__(
        self, url=None, client_id=None, secret_key=None, verify=False
    ):
        """
        Initialize Vectra Saas client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - required
        :param secret_key: API Secret Key for authentication - required
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(
            url=url,
            client_id=client_id,
            secret_key=secret_key,
            verify=verify,
        )
        url = VectraSaaSClient._remove_trailing_slashes(url)
        self.base_url = url
        self.version = 3.1
        self.url = f"{url}/api/v{self.version}"

    @staticmethod
    def _generate_entity_params(args):
        """
        Generate query parameters for detections based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "entity_type",
            "is_prioritized",
            "last_detection_timestamp_gte",
            "name",
            "note_modified_timestamp_gte",
            "ordering",
            "page",
            "page_size",
            "state",
            "tags",
            "type",
        ]
        deprecated_keys = ["entity_type"]
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    @staticmethod
    def _generate_entity_scoring_params(args):
        """
        Generate query parameters for detections based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "entity_type",
            "event_timestamp_gte",
            "from",
            "include_score_decreases",
            "limit",
            "type",
        ]
        deprecated_keys = ["entity_type"]
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    def get_all_entities(self, **kwargs):
        """
        Generator to retrieve all entities - all parameters are optional
        :param is_prioritized',
        :param entity_type', "account","host","account,host"
        :param ordering',
        :param last_detection_timestamp_gte',
        :param name',
        :param note_modified_timestamp_gte',
        :param page',
        :param page_size',
        :param state:
        :param tags:
        """
        resp = self._request(
            method="get",
            url=f"{self.url}/entities",
            params=self._generate_entity_params(kwargs),
        )
        yield resp
        while resp.json()["next"]:
            resp = self._request(method="get", url=resp.json()["next"])
            yield resp

    def get_entity_by_id(self, entity_id=None, **kwargs):
        """
        :param is_prioritized',
        :param entity_type', "account","host","account,host" - required
        :param ordering',
        :param last_detection_timestamp_gte',
        :param name',
        :param note_modified_timestamp_gte',
        :param page',
        :param page_size',
        :param state:
        :param tags:
        """
        params = self._generate_entity_params(kwargs)
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if "entity_type" not in params:
            raise ValueError("Must provide entity_type.")

        return self._request(
            method="get", url=f"{self.url}/entities/{entity_id}", params=params
        )

    def get_entity_scoring(self, **kwargs):
        """
        :param include_score_decreases:
        :param from:
        :param limit:
        :param event_timestamp_gte:
        """
        return self._request(
            method="get",
            url=f"{self.url}/events/entity_scoring",
            params=self._generate_entity_scoring_params(kwargs),
        )


class VectraSaaSClientV3_2(VectraSaaSClientV3_1):
    def __init__(
        self, url=None, client_id=None, secret_key=None, verify=False
    ):
        """
        Initialize Vectra Saas client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - required
        :param secret_key: API Secret Key for authentication - required
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(
            url=url,
            client_id=client_id,
            secret_key=secret_key,
            verify=verify,
        )
        url = VectraSaaSClient._remove_trailing_slashes(url)
        self.base_url = url
        self.version = 3.2
        self.url = f"{url}/api/v{self.version}"

    @staticmethod
    def _generate_group_params(args):
        """
        Generate query parameters for groups based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "account_ids",
            "account_names",
            "description",
            "importance",
            "last_modified_by",
            "last_modified_timestamp",
            "name",
            "page_size",
            "type",
        ]
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid group query parameter"
                )
        return params

    def get_all_groups(self, **kwargs):
        """
        Generator to retrieve all groups - all parameters are optional
        :param account_ids
        :param account_names
        :param importance
        :param description
        :param last_modified_timestamp
        :param last_modified_by
        :param name:
        """
        resp = self._request(
            method="get",
            url=f"{self.url}/groups",
            params=self._generate_group_params(kwargs),
        )
        yield resp
        while resp.json()["next"]:
            resp = self._request(method="get", url=resp.json()["next"])
            yield resp

    def get_group_by_id(self, group_id=None, **kwargs):
        """
        Get groups by id
        :param rule_id: id of group to retrieve
        """
        if not group_id:
            raise ValueError("Must provide group_id.")
        return self._request(
            method="get",
            url=f"{self.url}/groups/{group_id}",
            params=self._generate_group_params(kwargs),
        )

    def get_group_by_name(self, name=None, description=None):
        """
        Get groups by name or description
        :param name: Name of group*
        :param description: Description of the group*
        *params are to be read as OR
        """
        if name and description:
            raise Exception("Can only provide a name OR a description")
        if name:
            response = next(self.get_all_groups(name=name, type="account"))
        elif description:
            response = next(
                self.get_all_groups(description=description, type="account")
            )
        return response.json()["results"]

    def create_group(
        self,
        name=None,
        description="",
        type="",
        members=[],
        importance="Medium",
        **kwargs,
    ):
        """
        Create group
        :param name: name of the group to create
        :param description: description of the group
        :param type: type of the group to create (domain/host/ip)
        :param members: list of account ids to add to group
        :param importance: importance of the entities in this list [high,medium,low]
        :param rules: list of triage rule ids to add to group
        :rtype requests.Response:
        """
        # TODO: validate type
        # TODO: convert importance from string to int
        # TODO: validate k,v
        if not name:
            raise ValueError("missing required parameter: name")
        if not isinstance(members, list):
            raise TypeError("members must be type: list")
        if not importance:
            raise ValueError("missing required parameter: importance")

        payload = {
            "name": name,
            "description": description,
            "type": type,
            "members": members,
            "importance": importance,
        }

        for k, v in kwargs.items():
            if not isinstance(v, list):
                raise TypeError(f"{k} must be of type: list")
            payload[k] = v

        return self._request(method="post", url=f"{self.url}/groups", json=payload)

    def update_group(
        self, group_id, name=None, description=None, members=[], append=False
    ):
        """
        Update group
        :param group_id: id of group to update
        :param name: name of group
        :param description: description of the group
        :param members: list of host ids to add to group
        :param append: set to True if appending to existing list (boolean)
        """

        if not isinstance(members, list):
            raise TypeError("members must be type: list")

        group = self.get_group_by_id(group_id=group_id).json()
        try:
            id = group["id"]
        except KeyError:
            raise KeyError(f"Group with id {str(group_id)} was not found")

        # Transform existing members into flat list as API returns dicts for host & account groups
        if append:
            if group["type"] in ["domain", "ip"]:
                for member in group["members"]:
                    members.append(member)
            elif group["type"] == "account":
                for member in group["members"]:
                    members.append(member["uid"])
            else:
                for member in group["members"]:
                    members.append(member["id"])
        # Ensure members are unique
        members = list(set(members))

        name = name if name else group["name"]
        description = description if description else group["description"]

        payload = {"name": name, "description": description, "members": members}
        return self._request(
            method="patch", url=f"{self.url}/groups/{id}", json=payload
        )

    def delete_group(self, group_id=None):
        """
        Delete group
        :param group_id:
        detections
        """
        if not group_id:
            raise ValueError("Must provide group_id.")
        return self._request(method="delete", url=f"{self.url}/groups/{group_id}")


class VectraSaaSClientV3_3(VectraSaaSClientV3_2):
    def __init__(
        self, url=None, client_id=None, secret_key=None, verify=False
    ):
        """
        Initialize Vectra Saas client
        :param url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param client_id: API Client ID for authentication - required
        :param secret_key: API Secret Key for authentication - required
        :param verify: Verify SSL (default: False) - optional
        """
        super().__init__(
            url=url,
            client_id=client_id,
            secret_key=secret_key,
            verify=verify,
        )
        url = VectraSaaSClient._remove_trailing_slashes(url)
        self.base_url = url
        self.version = 3.3
        self.url = f"{url}/api/v{self.version}"

    @staticmethod
    def _generate_host_params(args):
        """
        Generate query parameters for hosts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "c_score",
            "c_score_gte",
            "certainty",
            "key_asset",
            "last_detection_timestamp",
            "last_source",
            "mac_address",
            "max_id",
            "min_id",
            "name",
            "note_modified_timestamp_gte",
            "ordering",
            "page",
            "page_size",
            "privilege_category",
            "privilege_level",
            "privilege_level_gte",
            "state",
            "t_score",
            "t_score_gte",
            "tags",
            "threat",
        ]
        deprecated_keys = []
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid hosts query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    @staticmethod
    def _generate_account_event_params(args):
        """
        Generate query parameters for accounts based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = ["from", "limit"]
        deprecated_keys = []
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid detection query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return params

    @staticmethod
    def _generate_vectramatch_params(args):
        """
        Generate query parameters for groups based on provided args
        :param args: dict of keys to generate query params
        :rtype: dict
        """
        params = {}
        valid_keys = [
            "desired_state",
            "device_serial",
            "device_serials",
            "file",
            "notes",
            "uuid",
        ]
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid group query parameter"
                )
        return params

    @staticmethod
    def _generate_detection_events_params(args):
        """
        Generate query parameters for detection events based on provided args
        :param from:
        :param limit:
        :param event_timestamp_gte
        :param event_timestamp_lte
        :param type
        :param entity_type
        :param include_info_category
        :param include_triaged
        :param detection_id
        """
        params = {}
        valid_keys = [
            "detection_id",
            "entity_type",
            "event_timestamp_gte",
            "event_timestamp_lte",
            "from",
            "include_info_category",
            "include_triaged",
            "limit",
            "type",
        ]
        for k, v in args.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid group query parameter"
                )
        return params

    def get_vectramatch_enablement(self, **kwargs):
        """
        Determine enablement state of desired device
        :param device_serial: serial number of device (required)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "device_serial" not in params:
            raise ValueError("Device serial number is required.")
        resp = self._request(
            method="get", url=f"{self.url}/vectra-match/enablement", params=params
        )
        return resp

    def set_vectramatch_enablement(self, **kwargs):
        """
        Set desired enablement state of device
        :param device_serial: serial number of device (required)
        :param desired_state: boolean True or False (required)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "device_serial" not in params:
            raise ValueError("Device serial number is required.")

        if "desired_state" not in params:
            raise ValueError("Desired state is required (boolean).")
        resp = self._request(
            method="post", url=f"{self.url}/vectra-match/enablement", json=params
        )
        return resp

    def get_vectramatch_stats(self, **kwargs):
        """
        Retrieve vectra-match stats
        :param device_serial: serial number of device (optional)
        """
        resp = self._request(
            method="get",
            url=f"{self.url}/vectra-match/stats",
            params=self._generate_vectramatch_params(kwargs),
        )
        return resp

    def get_vectramatch_status(self, **kwargs):
        """
        Retrieve vectra-match status
        :param device_serial: serial number of device (optional)
        """
        resp = self._request(
            method="get",
            url=f"{self.url}/vectra-match/status",
            params=self._generate_vectramatch_params(kwargs),
        )
        return resp

    def get_vectramatch_available_devices(self):
        """
        Retrieve devices that can be enabled for vectra-match
        """
        resp = self._request(
            method="get", url=f"{self.url}/vectra-match/available-devices"
        )
        return resp

    def get_vectramatch_rules(self, **kwargs):
        """
        Retrieve vectra-match rules
        :param uuid: uuid of an uploaded ruleset (required)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "uuid" not in params:
            raise ValueError("Ruleset uuid must be provided.")
        resp = self._request(
            method="get", url=f"{self.url}/vectra-match/rules", params=params
        )
        return resp

    def upload_vectramatch_rules(self, **kwargs):
        """
        Upload vectra-match rules
        :param file: name of ruleset desired to be uploaded (required)
        :param notes: notes about the uploaded file (optional)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "file" not in params:
            raise ValueError("A ruleset filename is required.")
        if "notes" not in params:
            params["notes"] = ""
        headers = {"Authorization": self.headers["Authorization"]}
        resp = self._request(
            method="post",
            url=f"{self.url}/vectra-match/rules",
            headers=headers,
            files={"file": open(f"{params['file']}", "rb")},
            data={"notes": params["notes"]},
        )
        return resp

    def delete_vectramatch_rules(self, **kwargs):
        """
        Retrieve vectra-match rules
        :param uuid: uuid of an uploaded ruleset (required)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "uuid" not in params:
            raise ValueError(
                "Must provide the uuid of the desired ruleset to be deleted."
            )
        resp = self._request(
            method="delete", url=f"{self.url}/vectra-match/rules", json=params
        )
        return resp

    def get_vectramatch_assignment(self):
        """
        Retrieve ruleset assignments for vectra-match
        """
        resp = self._request(method="get", url=f"{self.url}/vectra-match/assignment")
        return resp

    def set_vectramatch_assignment(self, **kwargs):
        """
        Assign ruleset to device
        :param uuid: uuid of the ruleset to be assigned (required)
        :param device_serials: list of devices to assign the ruleset (required)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "uuid" not in params:
            raise ValueError("Must provide the ruleset uuid")
        if "device_serials" not in params:
            raise ValueError(
                "Must provide the serial number(s) of the device(s) to be assigned."
            )
        elif not isinstance(params["device_serials"], list):
            params["device_serials"] = params["device_serials"].split(",")
        resp = self._request(
            method="post", url=f"{self.url}/vectra-match/assignment", json=params
        )
        return resp

    def delete_vectramatch_assignment(self, **kwargs):
        """
        Assign ruleset to device
        :param uuid: uuid of the ruleset to be assigned (required)
        :param device_serial: serial of device (required)
        """
        params = self._generate_vectramatch_params(kwargs)
        if "uuid" not in params:
            raise ValueError("Must provide the ruleset uuid")
        if "device_serial" not in params:
            raise ValueError("Must provide the device serial number.")
        resp = self._request(
            method="delete", url=f"{self.url}/vectra-match/assignment", json=params
        )
        return resp

    def get_all_hosts(self, **kwargs):
        """
        Generator to retrieve all hosts - all parameters are optional
        :param c_score: certainty score (int) - will be removed with deprecation of v1 of api
        :param c_score_gte: certainty score greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param certainty: certainty score (int)
        :param last_detection_timestamp: timestamp of last activity on hosts (datetime)
        :param max_id: maximum ID of hosts returned
        :param min_id: minimum ID of hosts returned
        :param ordering: field used to sort response
        :param page: page number to return (int)
        :param page_size: number of object to return in response (int)
        :param state: state of hosts (active/inactive)
        :param t_score: threat score (int) - will be removed with deprecation of v1 of api
        :param t_score_gte: threat score is greater than or equal to (int) - will be removed with deprecation of v1 of api
        :param tags: tags assigned to hosts; this uses substring matching
        :param key_asset: key asset (bool) - will be removed with deprecation of v1 of api
        :param threat: threat score (int)
        :param note_modified_timestamp_gte: note last modified timestamp greater than or equal to (datetime)
        """
        resp = self._request(
            method="get",
            url=f"{self.url}/hosts",
            params=self._generate_host_params(kwargs),
        )
        yield resp
        while resp.json()["next"]:
            resp = self._request(method="get", url=resp.json()["next"])
            yield resp

    def get_host_by_id(self, host_id=None, **kwargs):
        """
        Get hosts by id
        :param host_id: hosts id - required
        """
        if not host_id:
            raise ValueError("hosts id required")

        return self._request(
            method="get",
            url=f"{self.url}/hosts/{host_id}",
            params=self._generate_host_params(kwargs),
        )

    def get_entity_tags(self, entity_id=None, entity_type=None, type=None):
        """
        Get entity tags
        :param entity_id: detection ID. required
        :param entity_type: deprecated for type
        :param type: "account","host","account,host"
        """
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )

        params = {"entity_type": entity_type, "type": type}
        return self._request(
            method="get", url=f"{self.url}/tagging/entity/{entity_id}", params=params
        )

    def set_entity_tags(
        self, entity_id=None, entity_type=None, type=None, tags=[], append=False
    ):
        """
        Set  entity tags
        :param entity_id: - required
        :param entity_type or type: -required
        :param tags: list of tags to add to entity
        :param append: overwrites existing list if set to False, appends to existing tags if set to True
        Set to empty list to clear all tags (default: False)
        """
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )
        params = {"entity_type": entity_type, "type": type}
        if append and isinstance(tags, list):
            current_list = self.get_entity_tags(entity_id=entity_id).json()["tags"]
            payload = {"tags": current_list + tags}
        elif isinstance(tags, list):
            payload = {"tags": tags}
        else:
            raise TypeError("tags must be of type list")

        return self._request(
            method="patch",
            url=f"{self.url}/tagging/entity/{entity_id}",
            json=payload,
            params=params,
        )

    def get_host_tags(self, host_id=None):
        """
        Get hosts tags
        :param host_id: detection ID. required
        """
        if not host_id:
            raise ValueError("Must provide host_id.")
        return self._request(method="get", url=f"{self.url}/tagging/host/{host_id}")

    def set_host_tags(self, host_id=None, tags=[], append=False):
        """
        Set  hosts tags
        :param host_id: - required
        :param tags: list of tags to add to hosts
        :param append: overwrites existing list if set to False, appends to existing tags if set to True
        Set to empty list to clear all tags (default: False)
        """
        if not host_id:
            raise ValueError("Must provide host_id.")
        if append and isinstance(tags, list):
            current_list = self.get_host_tags(host_id=host_id).json()["tags"]
            payload = {"tags": current_list + tags}
        elif isinstance(tags, list):
            payload = {"tags": tags}
        else:
            raise TypeError("tags must be of type list")

        return self._request(
            method="patch", url=f"{self.url}/tagging/host/{host_id}", json=payload
        )

    def get_host_notes(self, host_id=None):
        """
        Get hosts notes
        :param host_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete hosts body, we alter the response content
        """
        if not host_id:
            raise ValueError("Must provide host_id.")
        hosts = self._request(method="get", url=f"{self.url}/hosts/{host_id}/notes")
        if hosts.status_code == 200:
            json_dict = {
                "status": "success",
                "host_id": str(host_id),
                "notes": hosts.json()["notes"],
            }
            hosts._content = json.dumps(json_dict).encode("utf-8")
        return hosts

    def get_host_note_by_id(self, host_id=None, note_id=None):
        """
        Get hosts notes
        :param host_id:
        :param note_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete hosts body, we alter the response content
        """
        if not host_id:
            raise ValueError("Must provide host_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        hosts = self._request(
            method="get", url=f"{self.url}/hosts/{host_id}/notes/{note_id}"
        )
        return hosts

    def set_host_note(self, host_id=None, note=""):
        """
        Set hosts note
        :param host_id: - required
        :param note: content of the note to set - required
        """
        if not host_id:
            raise ValueError("Must provide host_id.")

        if isinstance(note, str) and note != "":
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str and cannot be empty.")

        return self._request(
            method="post", url=f"{self.url}/hosts/{host_id}/notes", json=payload
        )

    def update_host_note(self, host_id=None, note_id=None, note="", append=False):
        """
        Set hosts note
        :param host_id: - required
        :param note: content of the note to set - required
        :param append: overwrites existing note if set to False, appends if set to True
        """
        if not host_id:
            raise ValueError("Must provide host_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        if append and isinstance(note, str):
            current_note = self.get_host_note_by_id(
                host_id=host_id, note_id=note_id
            ).json()["note"]
            if current_note:
                if len(note) > 0:
                    payload = {"note": f"{current_note}\n{note}"}
                else:
                    payload = {"note": current_note}
            else:
                payload = {"note": note}
        elif isinstance(note, str) and note != "":
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str and cannot be empty.")

        return self._request(
            method="patch",
            url=f"{self.url}/hosts/{host_id}/notes/{note_id}",
            json=payload,
        )

    def delete_host_note(self, host_id=None, note_id=None):
        """
        Set hosts note
        :param host_id: - required
        :param note_id - required
        """
        if not host_id:
            raise ValueError("Must provide host_id.")
        if not note_id:
            raise ValueError("Must provide note_id.")

        return self._request(
            method="delete", url=f"{self.url}/hosts/{host_id}/notes/{note_id}"
        )

    def get_entity_notes(self, entity_id=None, entity_type=None, type=None):
        """
        Get entity notes
        :param entity_id:
        :param entity_type or type:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete entity body, we alter the response content
        """
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )
        params = {"entity_type": entity_type, "type": type}
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        entity = self._request(
            method="get", url=f"{self.url}/entities/{entity_id}", params=params
        )
        if entity.status_code == 200:
            json_dict = {
                "status": "success",
                "entity_id": str(entity_id),
                "notes": entity.json()["notes"],
            }
            entity._content = json.dumps(json_dict).encode("utf-8")
        return entity

    def get_entity_note_by_id(
        self, entity_id=None, entity_type=None, type=None, note_id=None
    ):
        """
        Get entity notes
        :param entity_id:
        :param note_id:
        For consistency we return a requests.models.Response object
        As we do not want to return the complete entity body, we alter the response content
        """
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )
        params = {"entity_type": entity_type, "type": type}
        if not note_id:
            raise ValueError("Must provide note_id.")

        entity = self._request(
            method="get",
            url=f"{self.url}/entities/{entity_id}/notes/{note_id}",
            params=params,
        )
        return entity

    def set_entity_note(self, entity_id=None, entity_type=None, type=None, note=""):
        """
        Set entity note
        :param entity_id: - required
        :param note: content of the note to set - required
        """
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )
        params = {"entity_type": entity_type, "type": type}
        if isinstance(note, str) and note != "":
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str and cannot be empty.")

        return self._request(
            method="post",
            url=f"{self.url}/entities/{entity_id}/notes",
            json=payload,
            params=params,
        )

    def update_entity_note(
        self,
        entity_id=None,
        entity_type=None,
        type=None,
        note_id=None,
        note="",
        append=False,
    ):
        """
        Set entity note
        :param entity_id: - required
        :param note: content of the note to set - required
        :param append: overwrites existing note if set to False, appends if set to True
        """
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )
        params = {"entity_type": entity_type, "type": type}
        if not note_id:
            raise ValueError("Must provide note_id.")

        if append and isinstance(note, str):
            current_note = self.get_entity_note_by_id(
                entity_id=entity_id, note_id=note_id, entity_type=entity_type, type=type
            ).json()["note"]
            if current_note:
                if len(note) > 0:
                    payload = {"note": f"{current_note}\n{note}"}
                else:
                    payload = {"note": current_note}
            else:
                payload = {"note": note}
        elif isinstance(note, str) and note != "":
            payload = {"note": note}
        else:
            raise TypeError("Note must be of type str and cannot be empty.")

        return self._request(
            method="patch",
            url=f"{self.url}/entities/{entity_id}/notes/{note_id}",
            json=payload,
            params=params,
        )

    def delete_entity_note(
        self, entity_id=None, entity_type=None, type=None, note_id=None
    ):
        """
        Set entity note
        :param entity_id: - required
        :param note_id - required
        """
        if not entity_id:
            raise ValueError("Must provide entity_id.")
        if not entity_type and not type:
            raise ValueError(
                "Must provide entity_type or type('account','host','account,host')."
            )
        params = {"entity_type": entity_type, "type": type}
        if not note_id:
            raise ValueError("Must provide note_id.")

        return self._request(
            method="delete",
            url=f"{self.url}/entities/{entity_id}/notes/{note_id}",
            params=params,
        )

    def get_account_scoring(self, **kwargs):
        raise DeprecationWarning(
            "This function has been deprecated in the Vectra API client v3.3. Please use get_entity_scoring()"
        )

    def get_account_detection(self, **kwargs):
        raise DeprecationWarning(
            "This function has been deprecated in the Vectra API client v3.3. Please use get_detection_events()"
        )

    def get_detection_events(self, **kwargs):
        """
        Get detection events
        :param from:
        :param limit:
        :param event_timestamp_gte
        :param event_timestamp_lte
        :param type
        :param entity_type
        :param include_info_category
        :param include_triaged
        :param detection_id
        """
        return self._request(
            method="get",
            url=f"{self.url}/events/detections",
            params=self._generate_detection_events_params(kwargs),
        )

    def get_lockdown(self, **kwargs):
        params = {}
        valid_keys = ["type", "entity_type"]
        deprecated_keys = ["entity_type"]
        for k, v in kwargs.items():
            if k in valid_keys:
                if v is not None:
                    params[k] = v
            else:
                raise ValueError(
                    f"argument {str(k)} is an invalid campaign query parameter"
                )
            if k in deprecated_keys:
                param_deprecation(k)
        return self._request(method="get", url=f"{self.url}/lockdown", params=params)

    def get_health(self, cache=True, v_lans=True):
        """
        :param cache: (bool)
        :param v_lans: (bool)
        """
        return self._request(
            method="get",
            url=f"{self.url}/health",
            params={"cache": cache, "v_lans": v_lans},
        )

    def get_health_check(self, check=None):
        """
        Get health statistics for the appliance
        :param check: specific check to run - optional
            possible values are: cpu, disk, hostid, memory, network, power, sensors, system
        """
        if not check:
            return self._request(method="get", url=f"{self.url}/health")
        else:
            if not isinstance(check, str):
                raise ValueError("check need to be a string")
            return self._request(method="get", url=f"{self.url}/health/{check}")

    def get_users(self, username=None, role=None, last_login_gte=None):
        """
        :param username:
        :param role:
        :param last_login_gte:
        """
        params = {}
        if username:
            params["username"] = username
        if role:
            params["role"] = role
        if last_login_gte:
            params["last_login_gte"] = last_login_gte
        return self._request(method="get", url=f"{self.url}/users", params=params)
