# Introduction

This cheat sheet provides some best practice for developers to follow when choosing and using security questions to implement a "forgot password" web application feature.

# The Problem

There is no industry standard either for providing guidance to users or developers when using or implementing a Forgot Password feature. The result is that developers generally pick a set of dubious questions and implement them insecurely. They do so, not only at the risk to their users, but also--because of potential liability issues--at the risk to their organization. Ideally, passwords would be dead, or at least less important in the sense that they make up only one of several multi-factor authentication mechanisms, but the truth is that we probably are stuck with passwords just like we are stuck with Cobol. So with that in mind, what can we do to make the Forgot Password solution as palatable as possible?

# Choosing Security Questions and/or Identity Data

Most of us can instantly spot a bad "security question" when we see one. You know the ones we mean. Ones like "What is your favorite color?" are obviously bad. But as the [Good Security Questions](http://goodsecurityquestions.com/) web site rightly points out, "there really are NO GOOD security questions; only fair or bad questions".

The reason that most organizations allow users to reset their own forgotten passwords is not because of security, but rather to reduce their own costs by reducing their volume of calls to their help desks. It's the classic convenience vs. security trade-off, and in this case, convenience (both to the organization in terms of reduced costs and to the user in terms of simpler, self-service) almost always wins out.

So given that the business aspect of lower cost generally wins out, what can we do to at least raise the bar a bit?

Here are some suggestions. Note that we intentionally avoid recommending specific security questions. To do so likely would be counterproductive because many developers would simply use those questions without much thinking and adversaries would immediately start harvesting that data from various social networks.

## Desired Characteristics

Any security questions or identity information presented to users to reset forgotten passwords should ideally have the following four characteristics:

1. **Memorable**: If users can't remember their answers to their security questions, you have achieved nothing.
2. **Consistent**: The user's answers should not change over time. For instance, asking "What is the name of your significant other?" may have a different answer 5 years from now.
3. **Nearly universal**: The security questions should apply to as wide an audience as possible.
4. **Safe**: The answers to security questions should not be something that is easily guessed, or research (e.g., something that is matter of public record).

## Steps

### Step 1) Decide on Identity Data vs Canned Questions vs. User-Created Questions

Generally, a single HTML form should be used to collect all of the inputs to be used for later password resets.

If your organization has a business relationship with users, you probably have collected some sort of additional information from your users when they registered with your web site. Such information includes, but is not limited to:

- email address
- last name
- date of birth
- account number
- customer number
- last 4 of social security number
- zip code for address on file
- street number for address on file

For enhanced security, you may wish to consider asking the user for their email address first and then send an email that takes them to a private page that requests the other 2 (or more) identity factors. That way the email itself isn't that useful because they still have to answer a bunch of 'secret' questions after they get to the landing page.

On the other hand, if you host a web site that targets the general public, such as social networking sites, free email sites, news sites, photo sharing sites, etc., then you likely to not have this identity information and will need to use some sort of the ubiquitous "security questions". However, also be sure that you collect some means to send the password reset information to some out-of-band side-channel, such as a (different) email address, an SMS texting number, etc.

Believe it or not, there is a certain merit to allow your users to select from a set of several "canned" questions. We generally ask users to fill out the security questions as part of completing their initial user profile and often that is the very time that the user is in a hurry; they just wish to register and get about using your site. If we ask users to create their own question(s) instead, they then generally do so under some amount of duress, and thus may be more likely to come up with extremely poor questions.

However, there is also some strong rationale to requiring users to create their own question(s), or at least one such question. The prevailing legal opinion seems to be if we provide some sort of reasonable guidance to users in creating their own questions and then insist on them doing so, at least some of the potential liabilities are transferred from our organizations to the users. In such cases, if user accounts get hacked because of their weak security questions (e.g., "What is my favorite ice cream flavor?", etc.) then the thought is that they only have themselves to blame and thus our organizations are less likely to get sued.

Since OWASP recommends in the [Forgot Password Cheat Sheet](Forgot_Password_Cheat_Sheet.md) that multiple security questions should be posed to the user and successfully answered before allowing a password reset, a good practice might be to require the user to select 1 or 2 questions from a set of canned questions as well as to create (a different) one of their own and then require they answer one of their selected canned questions as well as their own question.

### Step 2) Review Any Canned Questions with Your Legal Department or Privacy Officer

While most developers would generally first review any potential questions with whatever relevant business unit, it may not occur to them to review the questions with their legal department or chief privacy officer. However, this is advisable because their may be applicable laws or regulatory / compliance issues to which the questions must adhere. For example, in the telecommunications industry, the FCC's Customer Proprietary Network Information (CPNI) regulations prohibit asking customers security questions that involve "personal information", so questions such as "In what city were you born?" are generally not allowed.

### Step 3) Insist on a Minimal Length for the Answers

Even if you pose decent security questions, because users generally dislike putting a whole lot of forethought into answering the questions, they often will just answer with something short. Answering with a short expletive is not uncommon, nor is answering with something like "xxx" or "1234". If you tell the user that they *should* answer with a phrase or sentence and tell them that there is some minimal length to an acceptable answer (say 10 or 12 characters), you generally will get answers that are somewhat more resistant to guessing.

### Step 4) Consider How To Securely Store the Questions and Answers

There are two aspects to this...storing the questions and storing the answers. Obviously, the questions must be presented to the user, so the options there are store them as plaintext or as reversible ciphertext. The answers technically do not need to be ever viewed by any human so they could be stored using a secure cryptographic hash (although in principle, I am aware of some help desks that utilize the both the questions and answers for password reset and they insist on being able to *read* the answers rather than having to type them in; YMMV). Either way, we would always recommend at least encrypting the answers rather than storing them as plaintext. This is especially true for answers to the "create your own question" type as users will sometimes pose a question that potentially has a sensitive answer (e.g., "What is my bank account \# that I share with my wife?").

So the main question is whether or not you should store the questions as plaintext or reversible ciphertext. Admittedly, we are a bit biased, but for the "create your own question" types at least, we recommend that such questions be encrypted. This is because if they are encrypted, it makes it much less likely that your company will be sued if you have some bored, rogue DBAs pursuing the DB where the security questions and answers are stored in an attempt to amuse themselves and stumble upon something sensitive or perhaps embarrassing.

In addition, if you explain to your customers that you are encrypting their questions and hashing their answers, they might feel safer about asking some questions that while potentially embarrassing, might be a bit more secure. (Use your imagination. Do we need to spell it out for you? Really???)

### Step 5) Periodically Have Your Users Review their Questions

Many companies often ask their users to update their user profiles to make sure contact information such as email addresses, street address, etc. is still up-to-date. Use that opportunity to have your users review their security questions. (Hopefully, at that time, they will be in a bit less of a rush, and may use the opportunity to select better questions.) If you had chosen to encrypt rather than hash their answers, you can also display their corresponding security answers at that time.

If you keep statistics on how many times the respective questions has been posed to someone as part of a Forgot Password flow (recommended), it would be advisable to also display that information. (For instance, if against your advice, they created a question such as "What is my favorite hobby?" and see that it had been presented 113 times and they think they might have only reset their password 5 times, it would probably be advisable to change that security question and probably their password as well.)

### Step 6) Authenticate Requests to Change Questions

Many web sites properly authenticate change password requests simply by requesting the current password along with the desired new password. If the user cannot provide the correct current password, the request to change the password is ignored. The same authentication control should be in place when changing security questions. The user should be required to provide the correct password along with their new security questions & answers. If the user cannot provide the correct password, then the request to change the security questions should be ignored. This control prevents both Cross-Site Request Forgery attacks, as well as changes made by attackers who have taken control over a users workstation or authenticated application session.

# Using Security Questions

Requiring users to answer security questions is most frequently done under two quite different scenarios:

- As a means for users to reset forgotten passwords. (See [Forgot Password Cheat Sheet](Forgot_Password_Cheat_Sheet.md).)
- As an additional means of corroborating evidence used for authentication.

If at anytime you intend for your users to answer security questions for both of these scenarios, it is *strongly* recommended that you use two different sets of questions / answers.

It should noted that using a security question / answer in addition to using passwords does ***not*** give you multi-factor authentication because both of these fall under the category of "what you know". Hence they are two of the *same* factor, which is not multi-factor. Furthermore, it should be noted that while passwords are a very weak form of authentication, answering security questions are generally is a much weaker form. This is because when we have users create passwords, we generally test the candidate password against some password complexity rules (e.g., minimal length &gt; 10 characters; must have at least one alphabetic, one numeric, and one special character; etc.); we usually do no such thing for security answers (except for perhaps some minimal length requirement). Thus good passwords generally will have much more entropy than answers to security questions, often by several orders of magnitude.

## Security Questions Used To Reset Forgotten Passwords

The [Forgot Password Cheat Sheet](Forgot_Password_Cheat_Sheet.md) already details pretty much everything that you need to know as a developer when *collecting* answers to security questions. However, it provides no guidance about how to assist the user in selecting security questions (if chosen from a list of candidate questions) or writing their own security questions / answers. Indeed, the [Forgot Password Cheat Sheet](Forgot_Password_Cheat_Sheet.md) makes the assumption that one can actually use additional *identity* data as the security questions / answers. However, often this is not the case as the user has never (or won't) volunteer it or is it prohibited for compliance reasons with certain regulations (e.g., as in the case of telecommunications companies and [CPNI](https://en.wikipedia.org/wiki/Customer_proprietary_network_information) data).

Therefore, at least some development teams will be faced with collecting more generic security questions and answers from their users. If you must do this as a developer, it is good practice to:

- briefly describe the importance of selecting a good security question / answer.
- provide some guidance, along with some examples, of what constitutes bad vs. fair security questions.

You may wish to refer your users to the [Good Security Questions](http://goodsecurityquestions.com/) web site for the latter.

Furthermore, since adversaries will try the "forgot password" reset flow to reset a user's password (especially if they have compromised the side-channel, such as user's email account or their mobile device where they receive SMS text messages), is a good practice to minimize unintended and unauthorized information disclosure of the security questions. This may mean that you require the user to answer one security question before displaying any subsequent questions to be answered. In this manner, it does not allow an adversary an opportunity to research all the questions at once. Note however that this is contrary to the advice given on the [Forgot Password Cheat Sheet](Forgot_Password_Cheat_Sheet.md) and it may also be perceived as not being user-friendly by your sponsoring business unit, so again YMMV.

Lastly, you should consider whether or not you should treat the security questions that a user will type in as a "password" type or simply as regular "text" input. The former can prevent shoulder-surfing attacks, but also cause more typos, so there is a trade-off. Perhaps the best advice is to give the user a choice; hide the text by treating it as "password" input type by default, but all the user to check a box that would display their security answers as clear text when checked.

## Security Questions As An Additional Means Of Authenticating

First, it bears repeating again...if passwords are considered weak authentication, then using security questions are even less robust. Furthermore, they are no substitute for true multi-factor authentication, or stronger forms of authentication such as authentication using one-time passwords or involving side-channel communications. In a word, very little is gained by using security questions in this context. But, if you must...keep these things in mind:

- Display the security question(s) on a separate page only *after* your users have successfully authenticated with their usernames / passwords (rather than only after they have entered their username). In this manner, you at least do not allow an adversary to view and research the security questions unless they also know the user's current password.
- If you also use security questions to reset a user's password, then you should use a *different* set of security questions for an additional means of authenticating.
- Security questions used for actual authentication purposes should regularly expire much like passwords. Periodically make the user choose new security questions and answers.
- If you use answers to security questions as a *subsequent* authentication mechanism (say to enter a more sensitive area of your web site), make sure that you keep the session idle time out very low...say less than 5 minutes or so, or that you also require the user to first re-authenticate with their password and then immediately after answer the security question(s).

# Related Articles

- [Forgot Password Cheat Sheet](Forgot_Password_Cheat_Sheet.md)
- [Good Security Questions web site](http://goodsecurityquestions.com/)