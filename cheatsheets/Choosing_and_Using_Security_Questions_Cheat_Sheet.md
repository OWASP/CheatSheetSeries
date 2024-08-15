# Choosing and Using Security Questions Cheat Sheet

## Introduction

**WARNING: Security questions are no longer recognized as an acceptable authentication factor per [NIST SP 800-63](https://pages.nist.gov/800-63-3/sp800-63b.html). Account recovery is just an alternate way to authenticate so it should be no weaker than regular authentication. See [SP 800-63B sec 5.1.1.2 paragraph 4](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5): *Verifiers SHALL NOT prompt subscribers to use specific types of information (e.g., “What was the name of your first pet?”) when choosing memorized secrets*.**

If you are curious, please have a look at this [study](https://www.microsoft.com/en-us/research/publication/its-no-secret-measuring-the-security-and-reliability-of-authentication-via-secret-questions/) by Microsoft Research in 2009 and this [study](https://research.google/pubs/pub43783/) performed at Google in 2015. The accompanying [Security blog](https://security.googleblog.com/2015/05/new-research-some-tough-questions-for.html) update includes an infographic on the issues identified with security questions.

**Please Note:** While there are no acceptable uses of security questions in secure software, this cheat sheet provides guidance on how to choose strong security questions for legacy purposes.

## Choosing Security Questions

### Desired Characteristics

Any security questions presented to users to reset forgotten passwords must meet the following characteristics:

| Characteristic | Explanation |
|----------------|-------------|
| Memorable | The user must be able to recall the answer to the question, potentially years after creating their account. |
| Consistent | The answer to the question must not change over time. |
| Applicable | The user must be able to answer the question.
| Confidential | The answer to the question must be hard for an attacker to obtain. |
| Specific | The answer should be clear to the user. |

### Types of Security Questions

Security questions fall into two main types. With *user defined* security questions, the user must choose a question from a list, and provide an answer to the question. Common examples are "What is your favourite colour?" or "What was your first car?"

These are easy for applications to implement, as the additional information required is provided by the user when they first create their account. However, users will often choose weak or easily discovered answers to these questions.

*System defined* security questions are based on information that is already known about the user. This approach avoids having to ask the user to provide specific security questions and answers, and also prevents them from being able to choose weak details. However it relies on sufficient information already being stored about the user, and on this information being hard for an attacker to obtain.

### User Defined Security Questions

#### Bad Questions

Any questions that do not have all of the characteristics discussed above should be avoided. The table below gives some examples of bad security questions:

| Question | Problem |
|----------|---------|
| When is your date of birth? | Easy for an attacker to discover. |
| What is your memorable date? | Most users will just enter their birthday. |
| What is your favourite movie? | Likely to change over time. |
| What is your favourite cricket team? | Not applicable to most users. |
| What is the make and model of your first car? | Fairly small range of likely answers. |
| What is your nickname? | This could be guessed by glancing through social media posts. |

Additionally, the context of the application must be considered when deciding whether questions are good or bad. For example, a question such as "What was your maths teacher's surname in your 8th year of school?" would be very easy to guess if it was using in a virtual learning environment for your school (as other students probably know this information), but would be much stronger for an online gaming website.

#### Good Questions

Many good security questions are not applicable to all users, so the best approach is to give the user a list of security questions that they can choose from. This allows you to have more specific questions (with more secure answers), while still providing every user with questions that they can answer.

The following list provides some examples of good questions:

- What is the name of a college you applied to but didn’t attend?
- What was the name of the first school you remember attending?
- Where was the destination of your most memorable school field trip?
- What was your maths teacher's surname in your 8th year of school?
- What was the name of your first stuffed toy?
- What was your driving instructor's first name?

Much like passwords, there is a risk that users will re-use recovery questions between different sites, which could expose the users if the other site is compromised. As such, there are benefits to having unique security questions that are unlikely to be shared between sites. An easy way to achieve this is to create more targeted questions based on the type of application. For example, on a share dealing platform, financial related questions such as "What is the first company you owned shares in?" could be used.

#### Allowing Users to Write Their Own Questions

Allowing users to write their own security questions can result in them choosing very strong and unique questions that would be very hard for an attacker to guess. However, there is also a significant risk that users will choose weak questions. In some cases, users might even set a recovery question to a reminder of what their password is - allowing anyone guessing their email address to compromise their account.

As such, it is generally best not to allow users to write their own questions.

#### Restricting Answers

Enforcing a minimum length for answers can prevent users from entering strings such as "a" or "123" for their answers. However, depending on the questions asked, it could also prevent users from being able to correctly answer the question. For example, asking for a first name or surname could result in a two letter answer such as "Li", and a colour-based question could be four letters such as "blue".

Answers should also be checked against a denylist, including:

- The username or email address.
- The user's current password.
- Common strings such as "123" or "password".

#### Renewing Security Questions

If the security questions are not used as part of the main authentication process, then consider periodically (such as when they are changing their passwords after expiration) prompting the user to review their security questions and verify that they still know the answers. This should give them a chance to update any answers that may have changed (although ideally this shouldn't happen with good questions), and increases the likelihood that they will remember them if they ever need to recover their account.

### System Defined Security Questions

System defined security questions are based on information that is already known about the user. The users' personal details are often used, including the full name, address and date of birth. However these can easily be obtained by an attacker from social media, and as such provide a very weak level of authentication.

The questions that can be used will vary hugely depending on the application, and how much information is already held about the user. When deciding which bits of information may be usable for security questions, the following areas should be considered:

- Will the user be able to remember the answer to the question?
- Could an attacker easily obtain this information from social media or other sources?
- Is the answer likely to be the same for a large number of users, or easily guessable?

## Using Security Questions

### When to Use Security Questions

Applications should generally use a password along with a second authentication factor (such as an OTP code) to authenticate users. The combination of a password and security questions **does not constitute MFA**, as both factors as the same (i.e. something you know)..

**Security questions should never be relied upon as the sole mechanism to authenticate a user**. However, they can provide a useful additional layer of security when other stronger factors are not available. Common cases where they would be used include:

- Logging in.
- Resetting a forgotten password.
- Resetting a lost MFA token.

#### Authentication Flow

Security questions may be used as part of the main authentication flow to supplement passwords where MFA is not available. A typical authentication flow would be:

- The user enters their username and password.
- If the username and password are correct, the user is presented with the security question(s).
- If the answers are correct, the user is logged in.

If the answers to the security questions are incorrect, then this should be counted as a failed login attempt, and the account lockout counter should be incremented for the user.

#### Forgotten Password or Lost MFA Token Flow

Forgotten password functionality often provides a mechanism for attackers to enumerate user accounts if it is not correctly implemented. The following flow avoids this issue by only displaying the security questions once the user has proved ownership of the email address:

- The user enters email address (and solves a CAPTCHA).
- The application displays a generic message such as "If the email address was correct, an email will be sent to it".
- An email with a randomly generated, single-use link is sent to the user.
- The user clicks the link.
- The user is presented with the security question(s).
- If the answer is correct, the user can enter a new password.

### How to Use Security Questions

#### Storing Answers

The answers to security questions may contain personal information about the user, and may also be re-used by the user between different applications. As such, they should be treated in the same way as passwords, and stored using a secure hashing algorithm such as Bcrypt. The [password storage cheat sheet](Password_Storage_Cheat_Sheet.md) contains further guidance on this.

#### Comparing Answers

Comparing the answers provided by the user with the stored answer in a case insensitive manner makes it much easier for the user. The simplest way to do this is to convert the answer to lowercase before hashing the answer to store it, and then lowercase the user-provided answer before comparing them.

It is also beneficial to give the user some indication of the format that they should use to enter answers. This could be done through input validation, or simply by recommending that the user enters their details in a specific format. For example, when asking for a date, indicating that the format should be "DD/MM/YYYY" will mean that the user doesn't have to try and guess what format they entered when registering.

#### Updating Answers

When the user updates the answers to their security questions, this should be treated as a sensitive operation within the application. As such, the user should be required to re-authenticate themselves by entering their password (or ideally using MFA), in order to prevent an attacker updating the questions if they gain temporary access to the user's account.

#### Multiple Security Questions

When security questions are used, the user can either be asked a single question, or can be asked multiple questions at the same time. This provides a greater level of assurance, especially if the questions are diverse, as an attacker would need to obtain more information about the target user. A mixture of user-defined and system-defined questions can be very effective for this.

If the user is asked a single question out of a bank of possible questions, then this question **should not** be changed until the user has answered it correctly. If the attacker is allowed to try answering all of the different security questions, this greatly increases the chance that they will be able to guess or obtain the answer to one of them.
