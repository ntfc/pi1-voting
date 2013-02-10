# INSTALLATION
- you have to add libs/ folder to the project library.
  - In netbeans, just click go to the Projects tab, right click in Libraries,
and add the libs/ folder
- or add the [pi1-library](https://github.com/ntfc/pi1-library) netbeans project to the project libraries

# NOTES
 * use test package to test stuff
 * use test/gui to test the gui
 * voting scheme is implemented in org.evoting

# TODO
 - in netbeans, go to Window -> Actions Itens to see the TODO's in the code
 - create exceptions (in org.voting.exception)
 - validate client voting option (done)
 - validate receive votes (90% done)
 - validate parameters passed to Voting constrcutor (see the invalid values on papers...)
 - DONT USE A LIST TO STORE CANDIDATE NAMES NOR THE VOTES

#CODES
 - create a static class HomoCipher, that contains a `public static Cipher getChiper(code)`
 - PaillierSimple: 0x1
 - PaillierFast: 0x2
 - PaillierOutra: 0x3
 - ElGamal: 0x4
