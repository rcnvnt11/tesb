"""Service class for handling temporary email operations"""
from TempMail import TempMail


class EmailService:
    """Service class for handling temporary email operations"""

    def __init__(self, api_key=None):
        """
        Initialize the email service with an API key

        Args:
            api_key (str, optional): The API key for tempmail.lol service
        """
        self.client = TempMail(api_key if api_key else None)

    def create_inbox(self, options=None):
        """
        Creates a new temporary inbox

        Args:
            options (dict, optional): Inbox creation options
                - domain (str): Optional domain for the email
                - prefix (str): Optional prefix for the email

        Returns:
            object: The created inbox object with 'address' and 'token' attributes

        Raises:
            Exception: If inbox creation fails
        """
        if options is None:
            options = {}

        try:
            # Use the library's createInbox method
            inbox = self.client.createInbox(**options)
            return inbox
        except Exception as error:
            raise Exception(f"Failed to create inbox: {str(error)}")

    def check_inbox(self, token):
        """
        Checks inbox messages for a given token

        Args:
            token (str): The inbox access token

        Returns:
            list: Array of email objects

        Raises:
            Exception: If checking inbox fails
        """
        try:
            # Use the library's getEmails method
            emails = self.client.getEmails(token)
            return emails
        except Exception as error:
            raise Exception(f"Failed to check inbox: {str(error)}")
