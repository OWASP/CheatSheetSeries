# Introduction

This article provides a simple model to follow when implementing a *forgot password* web application feature.

# The Problem

There is no industry standard for implementing a **Forgot Password** feature. The result is that you see applications forcing users to jump through myriad hoops involving emails, special URLs, temporary passwords, personal security questions, and so on. In the end you have to reset it to a new value.

# Steps

## Step 1) Gather Identity Data or Security Questions

The first page of a secure Forgot Password feature asks the user for multiple pieces of hard data that should have been previously collected (generally when the user first registers). 

Steps for this are detailed in the identity section the Choosing and Using Security Questions Cheat Sheet [here](Choosing_and_Using_Security_Questions_Cheat_Sheet.md#step-1-decide-on-identity-data-vs-canned-questions-vs-user-created-questions).

At a minimum, you should have collected some data that will allow you to send the password reset information to some out-of-band side-channel, such as a (possibly different) email address or an SMS text number, etc. to be used in Step 3.

## Step 2) Verify Security Questions

After the form on Step 1 is submitted, the application verifies that each piece of data is correct for the given username. If anything is incorrect, or if the username is not recognized, the second page displays a generic error message such as *Sorry, invalid data*. 

If all submitted data is correct, Step 2 should display at least two of the user's pre-established personal security questions, along with input fields for the answers. It's important that the answer fields are part of a single HTML form.

Do not provide a drop-down list for the user to select the questions he wants to answer. Avoid sending the username as a parameter (hidden or otherwise) when the form on this page is submitted. The username should be stored in the server-side session where it can be retrieved as needed.

Because users' security questions / answers generally contains much less entropy than a well-chosen password (how many likely answers are there to the typical *What's your favorite sports team?* or *In what city where you born?* security questions anyway?), make sure you limit the number of guesses attempted and if some threshold is exceeded for that user (say 3 to 5), lock out the user's account for some reasonable duration (say at least 5 minutes) and then challenge the user with some form of challenge token per standard multi-factor workflow; see \#3, below) to mitigate attempts by hackers to guess the questions and reset the user's password. It is not unreasonable to think that a user's email account may have already been compromised, so tokens that do not involve email, such as SMS or a mobile soft-token, are best.

## Step 3) Send a Token Over a Side-Channel

After step 2, lock out the user's account immediately. Then SMS or utilize some other multi-factor token challenge with a randomly-generated code having 8 or more characters. 

This introduces an *out-of-band* communication channel and adds defense-in-depth as it is another barrier for a hacker to overcome. If the bad guy has somehow managed to successfully get past steps 1 and 2, he is unlikely to have compromised the side-channel. It is also a good idea to have the random code which your system generates to only have a limited validity period, say no more than 20 minutes or so. That way if the user doesn't get around to checking their email and their email account is later compromised, the random token used to reset the password would no longer be valid if the user never reset their password and the *reset password* token was discovered by an attacker. 

Of course, by all means, once a user's password has been reset, the randomly-generated token should no longer be valid.

## Step 4) Allow user to change password in the existing session

Step 4 requires input of the code sent in step 3 in the existing session where the challenge questions were answered in step 2, and allows the user to reset his password. Display a simple HTML form with one input field for the code, one for the new password, and one to confirm the new password. Verify the correct code is provided and be sure to enforce all password complexity requirements that exist in other areas of the application. 

As before, avoid sending the username as a parameter when the form is submitted. Finally, it's critical to have a check to prevent a user from accessing this last step without first completing steps 1 and 2 correctly. Otherwise, a [forced browsing](https://www.owasp.org/index.php/Forced_browsing) attack may be possible. Ensure the user changes their password and does not simply surf to another page in the application. 

The reset must be performed before any other operations can be performed by the user.

## Step 5) Logging

It is important to keep audit records when password change requests were submitted. This includes whether or not security questions were answered, when reset messages were sent to users and when users utilize them. It is especially important to log failed attempts to answer security questions and failed attempted use of expired tokens. This data can be used to detect abuse and malicious behavior. Data such as time, IP address, and browser information can be used to spot trends of suspicious use.

# Other Considerations

- Whenever a successful password reset occurs, all other sessions should be invalidated. Note the current session is already authenticated and does not require a login prompt.
- Strength of questions used for reset should vary based on the nature of the credential. Administrator credentials should have a higher requirement.
- The ideal implementation should rotate the questions asked in order to avoid automation.