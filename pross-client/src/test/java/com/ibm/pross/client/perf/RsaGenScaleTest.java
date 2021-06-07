package com.ibm.pross.client.perf;

import com.ibm.pross.client.encryption.ProactiveRsaEncryptionClient;
import com.ibm.pross.common.util.Exponentiation;
import com.ibm.pross.common.util.RandomNumberGenerator;
import com.ibm.pross.common.util.SecretShare;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaGenerator;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaPublicParameters;
import com.ibm.pross.common.util.crypto.rsa.threshold.proactive.ProactiveRsaShareholder;
import com.ibm.pross.common.util.shamir.Polynomials;
import com.ibm.pross.common.util.shamir.Shamir;
import org.junit.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class RsaGenScaleTest {
    /*** Important stats
     * increasing number of agents increases generation time
     * the variation is not important - shown in prev graphs
     * how the gen time differs for different key sizes
     */

    final int[] lengths = new int[]{3072, 4096, 7680};

    final BigInteger q_1536 = new BigInteger("2204891267454406652752310792683612450589537116917669323326891552347311938457100093581537827967081762234346471785288172616055126145282058996171039893000920659260237462752654077366498800638090932954205866161262102127830134273067358456895870059827560985624189538879164833147413832837629447428619755701673033346131071337204195691486238627439671691627431768763496188874175179839962733773722192089888595660254512265958883024849971593123212531270826834468228350351604859");
    final BigInteger p_1536 = new BigInteger("2139904791961410631988747835381473908787715041592096792518913961972506589871508622206775999463147465549195119463413552541523457421749347010551965317676737614643333811197164923622649162683906966310545427326120153800960976171469906585801940727553838993375383857519164848819336074974213829584830680391293326305951749136761940189334808400427030158860653223174644490302564240897794057786133542251201335633887578528405122467792993713526992541583780684769358715720424119");

    final BigInteger p_2048 = new BigInteger("26789109153698093444491682519914550624345683738791746812315986844939034998528608774869763133055245490136689791235492761484892368319957333492095263061008448395847020830328545144164739131344694540574225589833267273584093997627671431279311585610562355093269452058336622694871735081485175422794474067381113881838922932109333939845683909118190000040189880513650477109853755671040623404541990966995068224462793503328693297550771106340085125012814024940000382549519768992965994580164586302622739454921094922107410988100591506690893437716782947187000663827354937637689650245169429424356290724696231424301279923546224904877239");
    final BigInteger q_2048 = new BigInteger("25897664350266535754423199646068126368675405211839319738444688395165675631625694746164452032571376134736924632075044055925107944507346127645404699094905374055768314073545148297983594298185115505670618569256613856498559991544716652310269960943983330768715917410134200540146341372800852030756761479233139143756232794146088472929105742917707175216465717392787552429797038047687692709415016056784531668586599603439328415861874921757305357527755987525239905992549706132906952641079471504997657367472398942818084546196073616421036800251149204881808084170864606879139484527405267649876823030209514760737533835131558828153683");

    final BigInteger p_3840 = new BigInteger("7932080338618161731514740794069683001454933350352509383475322273012506123904689981603230379703916498504252723372307406867657913735829107943847897538120567342443270034569791411308895163919799794253183151653444065661960667147714860107689054034515375999087635491480826329591924611253656025481492993485509941625186495998913753006650999417494214057038926957009492337503385991834111099036723205809229849777500545063023618195678048044907948093110204568141618476042358907254666585698271086764704333138486363670926784211767336485736345189968976350279082952415746800025500661892134683095368021911458071775104920650447466228471748788461645250028702780883673678871689941348203893557042833823306429132366533851011824354955750887748689614308982902403363345338273199602018988683563519501951236982231737569704611899671902083879781776513819265991316553059033804848475942723717016823107654156446747055486188740422543021828812152814155521308176320993249591387214558328120311325096251359401328388136319612044181649666860904830002506714963446937377880228440219812327848494458297245908193543571323546367044575258641798631266301352385968777645901634930458152644838964269310520587");
    final BigInteger q_3840 = new BigInteger("7192373397972528237878022974182747204164180767914113883909861061448951446187598757547433396636212796232738224490833704567264514139110309353805014139355959393881112824716075369742500434311684971594791283316037179618024138409722403838547990289089556990509429078307878953773395228909188335504556832735120737760725627375992484136574372638388869782606509756378463019589385573157400363923553930669594289621219678486838070760460949999721551714708826176874831684398315773139930717609650490953860482898917512267583719052855947256025633094259312218559002459707884800902006611416603270616480167205303374916680420492087151842816105606230397859142191859003647706014791914505659282523064281655975323260799431294007862067026314344693997859898730290865054677016446784951006678858763219190492425727943637215178797465902609744043713541115992797619186174354242943545363363395043761369010062769672262443775653098529414514590757198242953398173452419606869091043816151577052791182121669166477220149030368821049961260893511480734175193369713676123952459905595525352760896606501794824308765196799161896336359153502606109044502022289097274384365213840987264569925881462568401258179");

    final List<BigInteger> primes = Arrays.asList(new BigInteger("2204891267454406652752310792683612450589537116917669323326891552347311938457100093581537827967081762234346471785288172616055126145282058996171039893000920659260237462752654077366498800638090932954205866161262102127830134273067358456895870059827560985624189538879164833147413832837629447428619755701673033346131071337204195691486238627439671691627431768763496188874175179839962733773722192089888595660254512265958883024849971593123212531270826834468228350351604859"),
            new BigInteger("2139904791961410631988747835381473908787715041592096792518913961972506589871508622206775999463147465549195119463413552541523457421749347010551965317676737614643333811197164923622649162683906966310545427326120153800960976171469906585801940727553838993375383857519164848819336074974213829584830680391293326305951749136761940189334808400427030158860653223174644490302564240897794057786133542251201335633887578528405122467792993713526992541583780684769358715720424119"),
            new BigInteger("26789109153698093444491682519914550624345683738791746812315986844939034998528608774869763133055245490136689791235492761484892368319957333492095263061008448395847020830328545144164739131344694540574225589833267273584093997627671431279311585610562355093269452058336622694871735081485175422794474067381113881838922932109333939845683909118190000040189880513650477109853755671040623404541990966995068224462793503328693297550771106340085125012814024940000382549519768992965994580164586302622739454921094922107410988100591506690893437716782947187000663827354937637689650245169429424356290724696231424301279923546224904877239"),
            new BigInteger("25897664350266535754423199646068126368675405211839319738444688395165675631625694746164452032571376134736924632075044055925107944507346127645404699094905374055768314073545148297983594298185115505670618569256613856498559991544716652310269960943983330768715917410134200540146341372800852030756761479233139143756232794146088472929105742917707175216465717392787552429797038047687692709415016056784531668586599603439328415861874921757305357527755987525239905992549706132906952641079471504997657367472398942818084546196073616421036800251149204881808084170864606879139484527405267649876823030209514760737533835131558828153683"),
            new BigInteger("7932080338618161731514740794069683001454933350352509383475322273012506123904689981603230379703916498504252723372307406867657913735829107943847897538120567342443270034569791411308895163919799794253183151653444065661960667147714860107689054034515375999087635491480826329591924611253656025481492993485509941625186495998913753006650999417494214057038926957009492337503385991834111099036723205809229849777500545063023618195678048044907948093110204568141618476042358907254666585698271086764704333138486363670926784211767336485736345189968976350279082952415746800025500661892134683095368021911458071775104920650447466228471748788461645250028702780883673678871689941348203893557042833823306429132366533851011824354955750887748689614308982902403363345338273199602018988683563519501951236982231737569704611899671902083879781776513819265991316553059033804848475942723717016823107654156446747055486188740422543021828812152814155521308176320993249591387214558328120311325096251359401328388136319612044181649666860904830002506714963446937377880228440219812327848494458297245908193543571323546367044575258641798631266301352385968777645901634930458152644838964269310520587"),
            new BigInteger("7192373397972528237878022974182747204164180767914113883909861061448951446187598757547433396636212796232738224490833704567264514139110309353805014139355959393881112824716075369742500434311684971594791283316037179618024138409722403838547990289089556990509429078307878953773395228909188335504556832735120737760725627375992484136574372638388869782606509756378463019589385573157400363923553930669594289621219678486838070760460949999721551714708826176874831684398315773139930717609650490953860482898917512267583719052855947256025633094259312218559002459707884800902006611416603270616480167205303374916680420492087151842816105606230397859142191859003647706014791914505659282523064281655975323260799431294007862067026314344693997859898730290865054677016446784951006678858763219190492425727943637215178797465902609744043713541115992797619186174354242943545363363395043761369010062769672262443775653098529414514590757198242953398173452419606869091043816151577052791182121669166477220149030368821049961260893511480734175193369713676123952459905595525352760896606501794824308765196799161896336359153502606109044502022289097274384365213840987264569925881462568401258179"));
    final List<BigInteger> moduli = Arrays.asList(p_1536.multiply(q_1536), p_2048.multiply(q_2048), p_3840.multiply(q_3840));
    final List<BigInteger> totients = Arrays.asList(p_1536.subtract(BigInteger.ONE).multiply(q_1536.subtract(BigInteger.ONE)), p_2048.subtract(BigInteger.ONE).multiply(q_2048.subtract(BigInteger.ONE)), p_3840.subtract(BigInteger.ONE).multiply(q_3840.subtract(BigInteger.ONE)));
    final int iterations = 1;
    final int startIter = 0;
    final int total_iterations =  iterations + startIter;
    final BigInteger e = BigInteger.valueOf(65537);
    List<Integer> numServersChoice = Arrays.asList(10, 20, 30);
    List<Double> thresChoice = Arrays.asList(0.5, 0.75, 1.0);
    long start, end;
    int maxAgents = 30;
    int minAgents = 3;
    int step = 1;

    @Test
    public void testOverallRsAKeyGen() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        File file1 = new File("RsaGenScaleTest.csv");
        file1.delete();

        // First line - indices on x axis - number of agents
        String firstLine = "";
        for (int numServers = minAgents; numServers <= maxAgents; numServers += step) {
            if (numServers > minAgents)
                firstLine = firstLine.concat(",");
            firstLine = firstLine.concat(String.valueOf(numServers));
        }
        firstLine = firstLine.concat("\n");

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(file1, true))) {
            bw.write(firstLine);
        }

        for (int s = 0; s < primes.size(); s = s + 2) {
            BigInteger p = primes.get(s);
            BigInteger q = primes.get(s+1);
            for (int numServers = minAgents; numServers <= maxAgents; numServers += step) {
                int threshold = (int) (numServers * 0.75);

                BigInteger accu = BigInteger.ZERO;
                for (int it = 0; it < total_iterations; it++) {

                    start = System.nanoTime();

                    ProactiveRsaGenerator.generateProactiveRsa(numServers,
                            threshold,
                            3076,
                            ProactiveRsaGenerator.DEFAULT_PARAMETER_R,
                            ProactiveRsaGenerator.DEFAULT_TAU,
                            p,
                            q);

                    end = System.nanoTime();

                    if (it >= startIter) {
                        accu = accu.add(BigInteger.valueOf(end - start));
                    }
                }

                try (BufferedWriter bw = new BufferedWriter(new FileWriter(file1, true))) {
                    if (numServers > minAgents)
                        bw.write(",");

                    bw.write(String.valueOf(accu.divide(BigInteger.valueOf(iterations))));

                    if (numServers == maxAgents)
                        bw.write("\n");
                }
                System.out.println(numServers + " : " + accu.divide(BigInteger.valueOf(iterations)));
            }
        }
    }

}
