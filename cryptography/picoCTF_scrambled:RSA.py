'''
CHALLENGE SOURCE:

flag format: picoCTF{

we are given a server to connect to

at connection, the server prints:

      flag: 204578876129699868186450527265468086991986914709697046880917252708099008428196811574921437621470246544358166637115244226074711582747098158241571529768442173194932458815951590875139663984042960691166201493256736779797136408179562688226896377154699704056145971559211738112786086870780571302425193554182490932005842464093389762221805457030945631914966685084156464353207705856100062842784327595817363444134844739447396944754140052969354030939681259667139814698639491255158499161982518542408769918706561292214801518655641041741858951032949277729699211449601020199575494097895044127338130597731129384125382775159507115699261550384456442321579075613475995233093934140032900968485505679011746043644181447434089917042820790824448279657953029088087151925102740624883916794602231359349332577521195343829007930325775837001593426034368595234489247460454838821123495469421241110360071504272525957391114804157817762143150323170990376650940613830375342014572225724840972671996307609403529905280997140539540877816492938013983198714695741080735890899080251975915120017468805102214740928547133752103412677924347690327799532933857008834149578111416335589708505866413894899646566255426786961220670630953244199518530882928135155671017499487307989175987234330507101164303825829150836523155504775355592176180772979664882178041846023092968141146110142322129953282559640392300462966077759762738791106484684718125769118114204679701747086591671249896420219554409616930716761052119841982719893776037293763213056708032639107457756932697046647426474933087265196176612745480298371355616755561675032176448619571890731974895119611590524117470241363761459209163096683585895489020514457852339752147580698377728675671791521677801232679851125524185716627437795591370210483607463202682178908868163325802768231746247483871552518641851303677156341205977864787305440468788421650917507110071083074624365124653631150847133545635069896575272641322023008623202411469413912514689703991267817099874941238105541635809828005295972788000733622651354837050802924829185880117115703047115751552079374025925994370522441562502107009115300503759864799958427837831669194651501416040563517060109020792858267970970922082124690475691355969855618580269469686150105459769684832924285092550765506566885508843059534871827642506690345998619165678681355108213730200521804565882014932845491162519814771082003923954067710638677300463282841884767331182172163171266614860746445733450077297052193753858416520835029769330720874536568084205091048771181735077102410340506271831493787831502267453575608053694494671641342339299900241465867184717419825991704128922397873161310527270755019127565982509399845475106176292640098676499381099561737154803909733828865800044119516088278228089147450050433615492246965852294021747972659363534951791763175523204704752419110401459111068978720698530160144245696285279090171252503792015256310666247705497298752346724939495907868976687796025838326648778935698834999668885243394947005033309996653396842982028449659831340718091119257766674079993476846447639072252833959039100882333565894301062569188323397046832616471696617424621820141624238975966219134099074047340941185950576506992640799397495239007891939476917426666336910886371944916306633806821400105603457825271563028862802521215579219686336300362318755876979432133550672359821365127454017261369062020830698145235349821478402586938596346087615042581126654956389525861785163367532387039658562822491303721985932420600126640040408859208378846028910316332278235702938936542724067094891742701690954271942636655058858631339595246400112672772179043487164279708361883841569194438884601806065243883792880516278826557206306352230385860521831758898778356080665100322556839308135431209819070940619210128253473718929811198078185925849162911089608643138015328634344686363212309236371625112660558260544382472953779132717300472137535284361474462370457792133576006733521833577529110051290304789602547162979988387747012312155437063708068919057276818073199922239592600642274202841664940743486671642233579375164160014983605322992299465377382717968126154630796885435225526922254926783800769181505559451265427955789597773247818742742052047348377327476402118227940938062168373098620364457785596741378582256841117514981744506992566341876149298501890968586054421643607438111057551880182053417974029366413696505140524799678405805595059412073285299259103626549895695268537076659490962963580987889353147304232720928859463493331460453925257342123938091387167884589663447477861887135945517929990985251074544904547876017822930734887794391605764273799286048011467305397096568871385122706174782841431181184785500732291141317397750477388534660601524188502580254346405404342064704455139472909090000835855080244984621457344786653092064429302748625491449016837527424690785476906711050353077239376883700865829369301958901332419094746200533008444275465513196432067713829988047105762047181933683226154982798915015091840597466379343696210391667494458620584318998937257862723378901288933926446112840420818839013777076245292330110670141668878954739721475216291773015012275419632353795962350200549455166253618410172837350746310471614708813682396576258610144537998088329257591573223851664768180257881588532001146605879854182709637529795716972313884139220567868130406808891472540698616842270440443850866736774699837640035406777907476061317313495502565771406767919395639463487020346923000022292926209720586866218474590476363503409777273285258035284029937337651569729083074842339250789167029497057008709758222012813689279399283031387036457824096489935608351063249271291092002163199424263747550333126078539811483619742686045417937322913917409670476078937636469847351899673308315450125956023022885108503218228913720789813246418884202817595639453575995663363232654369915825929617138663658622486974727837256396752485419469457260617626763470313873775047796830326026463444925792571885680557771423582572227644436533471827230153601574007769323198561406280739840229581405088651092143341191631298068708221197552282227323459784580983255050810326438937281369757965507213239612435724543742941544217503984102579863082857971704177739602909457222358086051298487897821871319599451904601130331422344618856981721613686291992046991092050665441496468250909503988400499309495585008524308537139025290883272754507627211383663746574799488662746506936824859141193392579966573545703759036326416126991547957723809585701823327540088652109721188167847769298675561619463435380735306654754732384367917253680542935549683668429173247912420176270724405179452857567697084013378654767588003156067293583033377660371338486866635855598462397902482454707562623197896916692895430208789762010187633622513883241982222729223821037988417507000247353838780493042534873400504668284332527939454388644708781227287001353501537699178717284247557823384766853837673191982340109796244705121440900402475777445434175448670059596260536181665421661414091679926983580939894993679852526448191156571178430337665574665146080517261611999428089773256662542489776875631933313403235913525506840609528117891148205566966803013247885808540049429299802199099741213659656469324730693300179356869502644330716030725932837291760419017364017048951329793094739823133951015940538246728426940898421284991362378765298816058965137358566462695103015820147596125478238622355514119696056695632878683385098971995404351003032575336060688726782478928390943232676283755472183849616754816811818406680256311480548864905991380299491373776231624642522650180731829409782895827955277880274282103915264274613607667637045596618606322575710315100397091448089452530220845605738336016503541101744692784195198743108150130579600975884196139543420533901224471664085158109146099784069186934766964173100409776128803830592966019977767697951664630993705483755077564428479831236117010648465500572242904836650749235748751156635216641870254398731770135128595081240830111840650477527621313276439401984951570162529444891961175209456482856229256821497997737366593655190971443393904186074436566478010349786890987087639072033241881344147408241659088808580
      n: 62410453115443516298341341919343997652792779162509068601970607976508804252222612304376976442647248101291495716053185631283557133289291034867192618266273821698721384229168415768212489801236517278323753157300895565993925836204050134665826010391511200315845693506924452902997025134807709174961812308652652335031
      e: 65537
      I will encrypt whatever you give me: 

each new connection gives different values for n and the flag

giving the input "hello" returns the encrypted version, most likely in rsa:

      I will encrypt whatever you give me: hello
      Here you go: 4004394760209372154737645559820645557529610074828119320587416599222514397906865731458632663884218942156953845476849183398962433826748549742385474981158477263189864912476118457855262058124534221630472345681152244809222223392082041878812206523733770856921326278759048392834043644384622894701201436599498604686753418316790680839223829227935277193771518555186428886591330073544105921240271759478040425879792142875155463041610469630193670701327628498828145803703485065633215720490820445452396046406595067471170842937495587861182288560158919676251760254802730902714691901003722106531776442609674015852167483787609900507769442006489270213466592826428812857552239763422276488739384698601146108471237687567355434281223302207175137948430757867539355614347068583081507439581498924437119554759104635958563601169668009611389334066761986217671137810876061813241694917956773752423778338263299832520495027128075418332762303919091265361567402487323064237340328442790874894999848510285728251194414677202654673691716238544550484505333358819081846834844398541233688220946717440066808947485538754296151726966816606327653135692233173918488289668994578871748313264397519967698373143704900659028115991114579183622949011904281979960116431862603127511778466032205556431236970004072650922005451416841728330283804694345648302352703168942914562446295853619714119817528667408540019620110309269827968593362536137987031169515862152502970535695094329438045582988372124749469428336590239083996098124845525016753702222929515397930012865913595520102708128032706828057304815220
      I will encrypt whatever you give me: 

I can try as many values as I like

I noticed that giving strings of different sizes returned encrypted values of different sizes:

      I will encrypt whatever you give me: a
      Here you go: 16350473981575242109094281761419266001680743481518586853578964985613575114464353371377123295732512757670250472182825474041224315067210135478248863585749313558715028807492028190334037272613784767352433586529964364618675276753286941020647394510654544441609532918610246529739347135563755154580637604417918082943
      I will encrypt whatever you give me: aa
      Here you go: 7974302748373429710661975390975376507885082870275345064766997312256114128789081642828466407225856841201356842915104367058675039175152753578739259598363209887785840598583933304244933518109994392253497278875116215445486993425032023110952737944397340882458093239087576180599139146287672745997833016689578795279916350473981575242109094281761419266001680743481518586853578964985613575114464353371377123295732512757670250472182825474041224315067210135478248863585749313558715028807492028190334037272613784767352433586529964364618675276753286941020647394510654544441609532918610246529739347135563755154580637604417918082943
      I will encrypt whatever you give me: aaa
      Here you go: 163504739815752421090942817614192660016807434815185868535789649856135751144643533713771232957325127576702504721828254740412243150672101354782488635857493135587150288074920281903340372726137847673524335865299643646186752767532869410206473945106545444416095329186102465297393471355637551545806376044179180829437974302748373429710661975390975376507885082870275345064766997312256114128789081642828466407225856841201356842915104367058675039175152753578739259598363209887785840598583933304244933518109994392253497278875116215445486993425032023110952737944397340882458093239087576180599139146287672745997833016689578795279930387303478340222156429485643657682334018666143737669680744715445657403217999694140587292497768551004692127434674036192694100614628694385748322967195704487580185166450384703101535646974891758292060357807765624532395412815740247860681714336737229256779662506881080055916586625809712022329322331341612076724065

Since the number of digits each time increased at a constant rate, I assumed that each letter was being encrypted on its own and concatenated onto the new ciphertext

With the hint from the name, I could also tell that each block was being added to the ciphertext in a random position, thus encrypting each character and scrambling their positions

      I will encrypt whatever you give me: a
      Here you go: 14592101271180453798694544202619645298354698938581367544561711264898466034092939728349493583454178662028384245290601499066728585762279351294288281062380086107166062179910775259624662273431775114191196208210182108984738077189285494413970804482652281336784017132289366000733544286820484036021259549397656770670
      I will encrypt whatever you give me: a
      Here you go: 14592101271180453798694544202619645298354698938581367544561711264898466034092939728349493583454178662028384245290601499066728585762279351294288281062380086107166062179910775259624662273431775114191196208210182108984738077189285494413970804482652281336784017132289366000733544286820484036021259549397656770670

When alone, the characters seemed to produce their own unique ciphertext

      I will encrypt whatever you give me: b
      Here you go: 31722040562036851679857039385508798960468480740006484654466633917705911246394977658275317373301531451045185738050113389080406885580226758520209046463812491017769154501141422002615135775121373952880030953180655172813830616507165471711835553219088026234956283365840574142462363261820449110995334019745618578582
      I will encrypt whatever you give me: ab
      Here you go: 1459210127118045379869454420261964529835469893858136754456171126489846603409293972834949358345417866202838424529060149906672858576227935129428828106238008610716606217991077525962466227343177511419119620821018210898473807718928549441397080448265228133678401713228936600073354428682048403602125954939765677067049501537783474198764242516751188762828753982446689119056688600288881782044942144028954316041186619554381127075258429505018322852596345355859324007554000412432823434181147753749324242024530049088644803098835689220123686821025387489799501915651427739710209080378750480518798964948709093396524300851969082607752
      I will encrypt whatever you give me: ba
      Here you go: 11173132892605605037979482289999353100998874074500412300280710945284723167978361346936238278847719820352512389753247147329460687512281601420457063632328192187622916463561524136222885445670362640249237020854759767152046344521276845604869389906022394374379672035519257023986530128363986407595491770195146465730031722040562036851679857039385508798960468480740006484654466633917705911246394977658275317373301531451045185738050113389080406885580226758520209046463812491017769154501141422002615135775121373952880030953180655172813830616507165471711835553219088026234956283365840574142462363261820449110995334019745618578582

However, when made into a part of a word, only the first character's unique text appeared in the ciphertext, which means that the encryption of a character is dependent on the characters behind it

Given this information, we now know why the flag given at the beginning is so long. It is made up of blocks where each character of the plaintext is encrypted into a block around 300 digits long

The first letter has no characters behind it, so its encryption should remain intact and we should be able to find it in the flag's ciphertext
the encryption of the letter 'p' definitely exists in the ciphertext, but the encryption of 'i' alone does not:
      flag: 58163649194720775284152957481365406544487871921088443804530137767542745534698392025658805656476776874914008131438747043806111260757557478297803861049559634807669860020367258401109673049244976268980587739702647324842045052238805091802524868465109483443327711645002819832346938683843638347901774696604377294649154128252474984656269987345789354379604867506948430173544666597177488530220478380234596965644220181284903456948214634984551861919298525865928662585820229337524806419747186681692641923113187379622372188786314770226538053212294224662487477849989521077668588777046573395117942300528652219078071677471980282717284995687082334343258738792261653578726588904888363756341975162562607879872046420964465119430655496320999067845330817001397090941231548218010459072540413167408230535807162951719934841290302896014381925447631273802623463593067262101387858054664094432348604981247023711937515121591438036629792574814404423596315217215969241328651763262465108650594817591142877907685214493054960481598059300249588347338630777541667398829198840823951781774767989066037325042036652154500919509604466823459979578613679975220698706804376912337181289104866234136394425105700138352298295972812382922151796392982206792631416216715123881483317893012621894308763990390877370366155850768013908135536666246003402480864237125236923796561366535639923418232206297458511150898768966205898536730100011966172110231197416017696752483674299333508190046631198123850744730813309341436453537800296481624147063113959293150906336908977147598970070899679972033215494720052302424531348814259932819276321876847263317580605687443735514965073425098342205080444318889226634194368316616630075507013331938691220938260793963300663930709096207949113675929601926985879989826813265832676882881553147683591736646970643345481986066946688698500719902742815848805430291003806322013995729787036395353922822104607230878676363575083389049662292250627733355142276714646837092103944695335361939571002195979987659432855731330195821180917067221189348895918699242029832776052758766272097460641609264227174571448382302379136711235601788454823627436206570706007269687366385297854152304715638527556741641137743302405767354630523613086997037333441020332113574019577708020746049789661632322224250456076337885332561815122956966236104021413741888158839131131272804716493802764698431197387366211132739503485718717459876430731157385998938558491322045637102997725012591262950675150982308472081650061676996067026053272256873566822065484458329200997781062937569430138588289807180290063758077844196928653695524156826928789341908376790526290254063098660524578609223891900546087680547096478489674965614251742695248503387027820386395153418783325336487327080637113546493599595876822825758957732771342608815942612399950021737524392448800780689430234333307218982040256080650778739746014285213493611469265995910041074493824772461683350237644100466745116409121386199575414537163932666276294804195654415242083802685571041857627760971846672800037472201481970035430553025650841128153366671417399406805000648700988111937670655795280688601985493570396655560874307444995160888337305576859183712939085560860106903657547698049745538323731920465555799563830305424323991373306256044671585132895912507498652190127690641240628137470657962674543910389825339361582614736597034924458102024270912251905084611914307219489044224084670303658805044833929417747128824532734724465254648688546194096379705425355322634594912938836934528237384385249234730185344505299142207570986961458777398677592711764493258579124933421595841321817250956918959933690232128868641612292453584727600720514588583824984353161206879866408131983807811552466006653855357079262131874589175715786218179274976329749908902250636377749150464122027184500977340306707880587371323260584772543392460017776523750366069008936260389255135318970426294661961596185796580804478754194034627350268276223952072454907323624318322149998401852380721344503782470034302950754772212916436828348935866626659526159971511250770187373185921833498759813944653709305717241561511412133438919747966319437154411654666889979841588691202537417529154971806314703892581642260948139089725587134794375313598560603238641288827005689905994615355731204867850119173260412700251295951713985297902810152084994723211728784485772588797377093504403906996123400027342090089595637668921575251852584983617727633006525181939284961246638336168287482651250984957134997481573300639688321758314777712215645383387472751883780461369496750724379382527516480712185112718403685778382804122937971425488902224058522697527999866314383222924569851537604571263443063489942405987210228414944896299323331109229800722634372806703081422579533123436934654511604639087410496170425238092700793889096724249568609253433583558238980219302345702176083625773427702381462465363489626354573507026126463957533760133702916716023224940694636557281537706651693183080317233518777095292686295264675724828835576295663176645179542674941849077084331289620648515989603819143319070964001898911065932746428436162684640446614669443333870958920416594199244409683076658955522701768190693039164617460963362460256027295843275391649941104630890121751299078366010545319841000664093536769726664285582686494610456303847282375765944383553417713355560881981005163944419764829888577441531938187818245215426106777474972461355576646080110752981642324447464587306717673161437826319719787413831103645052630428197693017636814562440057217226895785757376967611148378650667924147072374090755242690629890328721970369051461837902981784432968887819123104492210125473878388056684263202717487630449878651003296867071855546318369742217037605996826131950103032259317338306650906229699544359512916907868977510067641561528872447243870713005098757920403596604463330386205558710015339846264759852107475502396576357326465687795977859324498575385137998454865904243683217592061957735640755365867533527520785396553679984330750191753368140909261334614160129820983888762019566522877676769568200411735352470824754743797527536126227225802481233029702750907795880815435179979077150463248779523698257808799715837003356091906530083607843388946008335457755458247973912095576829380322662874877805850465235883469862012973261781550861097886439867115426800934062098380152360225134334117235012446878668524671052618649494070422915828901048831044950291562532129416664018369025896646944206574094378786240241913855793054943282453555711425100755265505568455617607792042157250137121091634971072992964400463732375807163608151656302308957587918908115680897136058945985887494823222050035750974216626118254545510078155018617118161999013479591945849731095321621374219560109029745322815831624942001650330549651333157730091445222270048586191543523167816613491563675404053855658876923526506073810174773268808006205039826172934698491044995687308676556549700388666513834847236745812155369500874894593242254032093108807469985936880296750083283774216556906134620771060616372881758204106176828978517190519883265940578422628703934579046599862682528529252802671738366850402334619843178411905436579492469463659517635626850858059823610934416711844389802521253990262122953760776133520126842589789335358441022164268318077862667032909815583588673023517067032051494952740687907267077657470697215877880544136427189584034446631373506452086734716373846231701532306695115257064576605606248611973408618184616722089298326092528989943284079068296104737714923208376446466615459033580481950252086938073743783531210039964750123393934889610220575187307435013179064447308482197579252313928739981715849912481281694218732201797248880224506740224364488114481964374237141975210535813194391245005047427475321837332695205843818466259040695694395421004861254253942309188685645728380476632673632432038041383595496149821472203184533446101772604941896964857734840150015236029676967335877858338524533437020785310937162975535499519467983449836244847201102509350085938861155157249776644355282414670242332807963212020257447138909807595207766856676571796228104656156912053291743576794967338098291699417217551523114134383
      n: 66120107135436156846329470718075062220155989548065883185242988053376729907486880715602641250075919184944282657812721541469183929188345758742378129767757732638441850320202866603123601151895199256309019842830218225210401943228287967310372401454656712524806262497983437221669692845549040000635615971445412938347
      e: 65537
      I will encrypt whatever you give me: p
      Here you go: 1721596924132865176326246510865059481759114287790768521449305496048159805930024958834733863077754166739882919884082395178177476798906603732504203665215450091950960446682345997957861367997522069870680437691233718128910486623413639442510570013835229829597281238292215179639298220679263141621671512388148331789
      I will encrypt whatever you give me: i
      Here you go: 56089205956244752471282491174744584790747486797523869676123452564891487132767929327550245229927369557415936089292748168962450035329339567361753399210968855578989936362625010952741486262670457738783034458212265548763363116390779490661654142941721218427539686411759310797582346855550236197683620548369758333666

The encryption of 'i' will only exist in the ciphertext if it was encrypted with all the correct characters behind it.

      I will encrypt whatever you give me: pi
      Here you go: 172159692413286517632624651086505948175911428779076852144930549604815980593002495883473386307775416673988291988408239517817747679890660373250420366521545009195096044668234599795786136799752206987068043769123371812891048662341363944251057001383522982959728123829221517963929822067926314162167151238814833178922065484458329200997781062937569430138588289807180290063758077844196928653695524156826928789341908376790526290254063098660524578609223891900546087680547096478489674965614251742695248503387027820386395153418783325336487327080637113546493599595876822825758957732771342608815942612399950021737524392448800780689

I do not need the information about the flag format, but it is helpful as it can help prove that what I was thinking is true. It also helps ensure that the code I wrote to find the flag works

To solve the challenge, we need to brute-force the flag. There is no other way because I do not have access to the source code of the server and so I do not know exactly how the characters are encrypted



I can start with an empty string called o
To brute-force each character, I have to ask the server to encrypt every single character in the ASCII table between '!' (33) and '_' (126)
As soon as I find the block in the ciphertext, that means this character exists in the plaintext

Implementation:
'''

r = remote("mercury.picoctf.net", 4484)

r.recvuntil(b'flag: ')
c = r.recvuntil(b'\n')
c = c[:-1].decode()

r.recvuntil(b'n: ')
n = r.recvuntil(b'\n')
n = int(n[:-1].decode())

r.recvuntil(b'e: ')
e = r.recvuntil(b'\n')
e = int(e[:-1].decode())

i = ord('!')
o = ""
while i < 127:
        
    r.recvuntil(b'give me: ')
    r.sendline(chr(i))
    r.recvuntil(b'Here you go: ')
    fc = r.recvline()[:-1].decode()
    
    if fc in c:
        print(chr(i))
        break
    
    i += 1

r.close()
'''

The code sends every possible character between '!' and '_' to the server and receives the encrypted version. If it finds the encrypted version in the original ciphertext, it will stop and print the found character.
As expected, this snippet prints 'p', the first character of the flag

The code only works for one character though, since an encryption with 2 characters for example will include 2 blocks.
Assuming the first character was 'p', then this new cipher will have one block that I know exists in the ciphertext and another block that we will need to check
If I find the new block in the ciphertext, then I know the flag contains the two letters I entered as the first and second characters of the flag.

To do this I can modify the code to enter the saved flag + the character I am trying to brute-force
When I receive the encryption, it will contain blocks I found before, so I should remove them from the encryption
Then I can check if the encryption exists in the ciphertext

Implementation:
'''

r = remote("mercury.picoctf.net", 4484)

r.recvuntil(b'flag: ')
c = r.recvuntil(b'\n')
c = c[:-1].decode()

r.recvuntil(b'n: ')
n = r.recvuntil(b'\n')
n = int(n[:-1].decode())

r.recvuntil(b'e: ')
e = r.recvuntil(b'\n')
e = int(e[:-1].decode())

i = ord('!')
o = ""
saved = []

while '}' not in o:
    
    i = ord('!')
    while i < 127:
            
        r.recvuntil(b'give me: ')
        r.sendline(o + chr(i))
        print(o + chr(i)) #since the code can take a while, I put this line to monitor the progress
        
        r.recvuntil(b'Here you go: ')
        fc = r.recvline()[:-1].decode()
        
        for x in saved:
            fc = fc.replace(x, '')
        
        if fc in c:
            o += chr(i)
            saved.append(fc)
            break
        
        i += 1
    

print("Flag: " + o)


r.close()

'''

in my case, the execution stopped halfway through and returned an EOF error.
I assumed that the server closed after taking too many inputs, so I saved what I collected from the flag and restarted:
'''

r = remote("mercury.picoctf.net", 4484)

r.recvuntil(b'flag: ')
c = r.recvuntil(b'\n')
c = c[:-1].decode()

r.recvuntil(b'n: ')
n = r.recvuntil(b'\n')
n = int(n[:-1].decode())

r.recvuntil(b'e: ')
e = r.recvuntil(b'\n')
e = int(e[:-1].decode())

i = ord('!')
o = ""
saved = []

compare = "picoCTF{"
j = 0

while '}' not in o:
    
    i = ord('!')
    while i < 127:
        
        if j < len(compare):
            i = ord(compare[j])
            j += 1
        
        r.recvuntil(b'give me: ')
        r.sendline(o + chr(i))
        print(o + chr(i)) #since the code can take a while, I put this line to monitor the progress
        
        r.recvuntil(b'Here you go: ')
        fc = r.recvline()[:-1].decode()
        
        for x in saved:
            fc = fc.replace(x, '')
        
        if fc in c:
            o += chr(i)
            saved.append(fc)
            break
        
        i += 1
    

print("Flag: " + o)


r.close()

'''

'''