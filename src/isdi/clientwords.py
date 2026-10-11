"""Client IDs made of four random words, such as "amber-otter-canyon-teapot".

From Sherloc (github.com/beauregardhenry/sherloc).

An ID names a consultation in the database and the session. It says nothing
about the client, the date or how many clients came before, and it is easy to
read aloud or write down.

The words are everyday and neutral (nature, food, colours, household
objects), chosen to be safe to see on a screen or a piece of paper. Words about
violence, injury, bodies, surveillance, alcohol, religion or politics were left
out, and so were brand names and hard-to-spell words. tests/test_client_ids.py
checks the list against a set of words that must never appear.

Each installation draws its own 2,048 of these words the first time it makes
an ID and keeps them in client-words.key in ISDi's config folder, readable by
the owner only. The full list is public in this repository; which words an
installation uses is not. The IDs are
unpredictable either way, because each word is drawn with the `secrets`
module. Four distinct words from 2,048 give about 1.7e13 possible IDs.
"""

import os
import secrets
from pathlib import Path
from typing import Callable, Sequence, Union

_RANDOM = secrets.SystemRandom()

WORDS: tuple[str, ...] = tuple("""
aardvark abacus abalone able absolute acacia academy accordion accurate acorn acre
active adept adorable adroit adventure affable afternoon agate agenda agile airborne
airship airy aisle alabaster albatross album alcove alder alert algae alive alley
allspice almanac almond alpaca alphabet aluminum amber amble amethyst amiable ample
amulet amused anchor anchovy ancient anemone angelfish angle animated anise annex annual
anorak answer ant antelope antenna anvil apartment apex applause apple applique apricot
april apron apt aqua aquifer arbor arc arcade arch archive ardent arena armadillo
armchair armrest aroma arroyo artful artichoke artwork arugula ascot ash asparagus
aspect aspen aster asteroid astute atlas atoll atom atomic atrium attentive attic
audience august aurora author autumn avalanche avenue avid avocado award awl awning axis
axle azalea azure backpack backwater backyard badge badger badminton bagel bagpipe
baguette bake bakery balance balcony ballad balloon ballroom balmy balsa bamboo banana
bandana bandstand bandwagon banjo bank banner banquet banyan baobab bargain barge bark
barley barn barnacle barnyard barometer barrel barrow basalt baseball baseboard basement
basil basin basket basketry bassoon baster bathtub batik baton battery bauble bay bayou
bazaar beach beacon bead beading beagle beaker beaming bean beanbag beanie bear beaver
bed bedrock bedspread bee beech beehive beet beetle begonia beige bell bellhop bellows
belt beluga bench benign beret beryl beverage bib bicycle billabong billboard binder
birch birdbath birdhouse birthday biscotti biscuit bison bisque black blackbird blanket
blazer blender blimp blinds blini blissful blithe blizzard bloom blooming blossom blouse
blue bluebell blueberry bluebird bluegill bluejay blueprint bluff boardwalk boat boater
boathouse bobber bobbin bobolink bobwhite bog bold bolero bonnet bonny bookcase bookend
bookmark bookshelf bookshop boot bootee bottle bough boulder boulevard bounce bouncy
bountiful bouquet boutique bow bowl bowling bowtie box boxwood bracelet bracing bracken
bracket braid brainy bramble bran branch brass brave brawny bread breadbox breakfast
breeches breeze breezy bridge briefcase bright brilliant brine brioche brisk brisket
broadway brocade broccoli bronze brooch brook broom broth brown brownie browse brunch
brush bubble bubbly bucket buckeye buckle buckwheat bud buffalo buggy bugle build bulb
bulgur bulletin bumblebee bumper bun bundle bungalow bunny bunting buoy buoyant burgundy
burlap burrito burro burrow bus bushel busy butte butter buttercup butterfly butternut
buttery button cabbage cabin cabinet cable cacao cadence cafe cafeteria caftan cake
calcite calendar calf calico caliper calm calming camel camellia cameo camisole camomile
campfire campsite canal canary candid candle candy canister cannoli canoe canoeing
canola canopy canteen canvas canyon cap capable cape capital capri caption caramel
caravan caraway carbon card cardamom cardboard cardigan cardinal carefree careful
caribou caring carmine carnation carnival carol carousel carp carpet carpool carriage
carrot cart carton cartoon cartwheel carve cascade cashew cashmere casserole cassette
castle casual catalog catalpa catamaran cataract catbird catfish catkin catnip cauldron
cavern cayenne cedar ceiling celery cell cellar cello center central century cereal
certain cerulean chair chalet chalk chambray chameleon chapter charcoal chard charger
charm charming chasm checkbook checkers checklist cheddar cheery cheese chenille cherry
chess chest chestnut chick chickadee chicken chickpea chief chiffon chime chimney
chipmunk chipper chisel chive chocolate chorus chosen chowder chrome chukar chummy
churro chutney cicada cilantro cinder cinema cinnamon circle citrus civic civil clam
clamp clarinet classic classroom classy clay clean cleanly clear clearing cleat clement
clever cliff climb clipboard cloak clock clog closet cloud cloudbank cloudless cloudy
clove clover clubhouse coach coal coast coastal coaster coastline coat cobalt cobble
cobbler cocoa coconut cocoon cod coffee coffeepot cog colander collage collar collard
collect collie colorful colt columbine comb comedy comet comfy comic compact compass
complete composed compost concert concise condor cone confetti container content contest
cook cookbook cookie cool coop copper coral cordial corduroy corgi coriander cork
corkscrew cormorant corn cornbread corner cornet cornflake cornmeal corral corridor
cosmos costume cosy cot cottage cotton couch coulee countdown counter courtly courtyard
couscous cove coverall cow cowbird cozy crab cracker cradle craft crafty crag cranberry
crane crate crater cravat crayfish crayon cream creamer creamy creative creek creeper
crepe crescent crest crevasse crib cricket crimson crisp crochet crocus croissant crop
croquet croquette crossword crouton crow crown cruiser crumble crumpet crunchy crystal
cub cube cucumber cuddly culottes cultivar cultured cumin cumulus cup cupboard cupcake
cupola curious curlew curling curly currant curry curtain curve cushion custard cutlet
cyan cycling cyclone cylinder cymbal cypress dachshund daffodil dahlia dainty dairy
daisy dale damselfly dance dandelion dapper daring darning dawn daybreak daydream
daylight dazzling dear decade december decent deck deep deer deft delicate delighted
dell delta denim depot derby desert desk dessert detail devoted dew diadem dial dialogue
diamond diary diligent dill dimple diner dinghy diploma dipper direct director dirndl
discovery dish diving dock dogwood doily doll dollhouse dolphin dominoes donkey donut
doodle doorbell doorknob doormat doorstep doorway dot dove downpour downtown draft
dragonfly drawer dream dreamer dreamy dresser drift driftwood drill driveway drizzle
dropper drum duck duckling duet duffel dulcet dulcimer dumpling dune dunlin durable dusk
dutiful dynamic eager eagle early earmuff earnest earring earth earthy easel eastward
easy easygoing ebony echo eclair eclectic eclipse edamame eddy edition educated eggcup
eggnog eggplant egret eider elastic elated elder electric elegant element elephant
elevator elk ellipse elm eloquent ember emblem embroider emerald eminent emu enamel
enchanted enchilada encore endive endless energetic engaged engine enormous entrance
envelope epic episode equal equinox eraser errand escalator estuary etching ethical even
evening exact excited exhibit exotic expert explore eyeglass fable fabulous fair fairway
faithful fajita falafel falcon fallow familiar famous fan fancy farmhouse farmland farro
fast faucet fawn fearless feather feature february fedora feijoa feisty feldspar felt
felting fen fence fencepost fennel fern ferret ferry fervent festival festive fetch
fetching fez fiddle field fiery fiesta fig file filigree filter finale finch fine fir
firefly fireplace fireside fireworks firm fishing fit fizzy fjord flag flagpole flame
flamingo flannel flapjack flashcard flask flatbread flawless fleece fleet flexible
flicker flipper floral flounder flour flourish flowerpot flowery fluent fluffy flute
flutter flying foal foamy focused fog fold folder fond fondue football foothill footpath
footstool forage forecast forest fork formal fortunate fossil fountain fox foxglove
foyer fraction fragrant frame frank free freesia freeway fresco fresh freshet friday
friendly frittata fritter frock frog frond frontier frost frosty frothy frugal fuchsia
fudge fugue full funky funnel funny furnace furrow fuzzy gadget gadwall gaiter galaxy
gale gallant gallery galosh gangway gannet garage garden gardener gardenia garland
garlic garnet garnish gate gateway gather gauge gazebo gazelle gazette gear gecko
gelatin gelato gem generous genial gentle genuine geode geranium gerbil geyser giant
gift gifted giggle gilding ginger gingham ginkgo ginseng giraffe glacier glad glade
gladiolus glassy glaze gleaming glen glide glider glimmer glitter globe glorious
glossary glossy glow glowing glue goat goblet godwit goggles gold golden goldenrod
goldfinch goldfish golf gondola gong good goose gopher gorge gosling goulash gown
graceful gracious grackle grain granary grand granite granola grape grapevine graphite
grass grassy grateful grater gravel gravity gravy gray great grebe green greenery grid
griddle grill grosbeak grotto grouper grouse grove grow guava guidebook guitar gulf gull
gully gumbo gumdrop guppy gutsy gutter gymnasium gypsum haddock hail hairband hairpin
halibut hallway halo halter hamlet hammock hamster handbag handbook handle handshake
handsome handy hangar hanger happy harbor hardy hare harmless harmonica harmony harp
harrier harvest hat haven hawk hawthorn hay hayloft hayride haystack haze hazel hazelnut
hazy headband headland headline headscarf healthy hearth hearty heath heather heathland
hedge hedgehog hedgerow heirloom helium helix helmet helpful hemp henhouse heroic heron
herring hexagon hibiscus hickory highchair highland highway hike hiking hill hillside
hilltop hinge hippo hobby hockey holiday hollow holly hollyhock homestead hometown
homework honest honey honeybee honeydew honored hoodie hook hoop hop hopeful hopscotch
horizon horn hornbeam horse hose hostel hotcake hotel hour hourglass houseboat hubcap
hum humble humid hummock hummus hushed husk husky hyacinth hydrangea hydrogen ibex ibis
icebox icefall icicle icing iconic icy idea ideal idyllic igloo iguana immense impala
index indigo inkwell inlet inn interval inventive iris iron irrigate island isle islet
itinerary ivory ivy jackdaw jacket jackfruit jade jam jambalaya jamboree january jar
jasmine jasper jaunty jay jazzy jeep jelly jellybean jellyfish jersey jetty jewel jicama
jigsaw jingle jodhpurs jogging jolly journal journey jovial joyful jubilant jug juggle
juggling juice juicer juicy jukebox july jumper junco junction june jungle juniper just
kale kangaroo katydid kayak kayaking kazoo kebab keen keepsake kelp kerchief kernel
kestrel ketch ketchup kettle key keyboard keychain keynote keystone khaki kiln kilt
kimchi kimono kind kindly kingdom kinglet kiosk kitchen kite kitten kittiwake kiwi knish
knit knitting knob knoll knot koala kohlrabi krill kumquat label lace lacquer lacrosse
ladder ladle ladybug lagoon laidback lake lakeside lamb lamp landmark landscape lane
lantern laptop lark larkspur lasagna lasting latch laugh laundry laurel lavender lavish
lawn leading leaf leafy learn learned leather lecture ledge ledger leek legend leggings
lemon lemonade lemony lemur lenient lens lentil leotard lettuce level library lichen
licorice lid light likable lilac lily limber lime limestone limousine linden line linen
linguine listen literate lively llama loafer lobby lobster locker locket locust lodge
lofty log logical lollipop lookout loom loop lotus loupe lovely lowland loyal lucid
lucky luggage lullaby luminous lunar lunchbox lupine lush lute lychee lynx lyre lyric
macadamia macaroni macaw mace mackerel macrame magenta magical magnet magnifier magnolia
magpie mahogany mailbag mailbox mailroom majestic malachite mallard manatee mandarin
mandolin mango mangrove mantel mantis mantle manual map maple maraca marathon marble
marbles march margin marigold marimba marine marjoram marker market marmalade marmot
maroon marsh martin marzipan mascot mast mat matinee matter mattress mature mauve may
maze meadow meander meatball medal medallion meerkat mellow melody melon memento mend
menu merciful meringue merlin merry mesa metal meteor meteorite meter mica micron midday
midnight midway mighty mild milestone milkman milkshake mill millet millpond mimosa
mincemeat mindful mingle minivan mink minnow mint minty minuet minute mirror miso mist
misty mitten mix mixer mobile moccasin moderate modern modest mohair molasses molecule
moment monday monocle monsoon month monument moon moonbeam moonlight moonrise moor
moorhen moose mop moped moraine morning mortar mosaic moss mossy moth motto mound
mountain mouse mousse mudflat muesli muff muffin muffler mug mulberry mulch mule mural
murre museum mushroom musical muslin mussel mustard mutual myrtle nacho nap napkin
narrative narwhal natural nautical navy nearby neat nebula necklace nectar nectarine
needed needle neon nest netball nettle neutron newt nickel nifty nimble nimbus nitrogen
noble nocturnal noodle noon normal notable notebook noted notepad nougat nourished novel
november nozzle nucleus nugget nursery nut nuthatch nutmeg nylon oak oaken oar oasis oat
oatcake oatmeal obliging oboe obsidian ocarina ocean ocelot ochre october octopus
official ointment okra olden olive omelet onion onyx opal open opener opera opossum
optimal opulent orange orbit orca orchard orchestra orchid orderly oregano organ organic
organizer organza origami original oriole ornament ornate osprey ostrich otter ottoman
outcrop outgoing outing outline oval oven overall overcoat overlook overpass overture
owl oxbow oxygen oyster paddle paddock paella pageant pail paint painting paisley
pajamas palace palette palm pamphlet pan pancake panda panini panorama pansy pantry
papaya paperclip paprika parachute parade parakeet parasol parcel parfait parka parlor
parmesan parrot parsley parsnip particle partridge passage passport pasta pastel
pastoral pastry pasture patch patchwork pathway patient patio pattern pavement pavilion
pavlova pawpaw payday pea peaceful peach peacoat peak peanut pear pearl pebble pebbly
pecan pecorino pedal pelican pencil pendant pendulum penguin peninsula pennant pentagon
peony pepita pepper peppery peppy percale perch perfect pergola perky persimmon pesto
petal petite petrel petunia pewter pheasant phlox phoebe photon piano piccolo pickle
picnic pie pier pigeon piglet pilaf pillow pimento pin pinafore pinboard pine pineapple
pinecone pink pinking pinnacle pintail pinwheel pipe pipit pistachio pita pitcher pixel
pizza placid plaid plain planet plankton plant plantain planter plate plateau platinum
platter play playa playbook playful playhouse playroom plaza pleasant pleat plenty
pliers plot plover plow plucky plug plum plush poblano pocket podium poem poised polenta
polish polished polite pollen pollock polo pomelo poncho pond ponder pony poodle popcorn
poplar poplin popover poppy poppyseed popular porch porcupine porridge portrait positive
possum postage postcard poster pot potato potent potluck potpie pottery pouch practical
prairie praline prawn precious precipice preface prelude premiere premium prepared
pretty pretzel prime primrose principal printer prism pristine prized program projector
promenade prompt propeller proper proton proud prudent pudding puddle puffin pulley
pullover pulsar pumice pump pumpkin puppet puppy pure purple puzzle pyramid quail quaint
qualified quantum quarry quarter quartet quartz quasar quay quiche quick quiet quill
quilt quilting quince quinoa quiz rabbit raccoon rack racquet radiant radio radish
radius raffia raft railway rain rainbow raincoat raindrop rainfall raisin rake ramekin
ramen ranch rapid rapids rare raspberry rational rattan rattle raven ravine ravioli
rayon read ready receipt receptive recess recipe recital red redbud redstart redwood
reed reef reel refined refrain regal regular rehearsal reindeer relax relaxed relay
reliable relish remote renewed resolute rest restful retriever reunion rhea rhino
rhubarb rhythm ribbon rice rich rickshaw ricotta riddle ridge rigatoni rill ring ripple
risotto river riverbank riverbed rivet roadmap roam robe robin robust rock rocker rocket
rockpool rocky roll roller rolling romper rooftop rook roomy rooster root rose rosemary
rosette rosewood rosy rotunda round rousing roux row rowan rowboat rowing royal ruby
rudder rug rugby rugged ruler runnel running runway rural rush rusk russet rust rustic
rutabaga rye sack saddle safe saffron sage sail sailboat sailing salad salmon salsa
saltine salty samosa sampler sand sandal sandbank sandbar sandbox sander sandpiper
sandstone sandwich sandy sap sapphire sapsucker sardine sarong sash sassafras satchel
satin satisfied saturday sauce saucepan saucer sausage savanna savor savvy saw saxophone
scale scallion scallop scarecrow scarf scarlet scaup scenic school scissors scone scoop
scooter scoter scrapbook scree screen screw scroll sculpture sea seahorse seal seashell
seashore seaside season seasoned seating seaweed second secure sedan seed seedling
seesaw sensible sepia september sequin sequoia serenade serene sesame settled sew shady
shaker shale shallot sharp shawl shed sheep sheer shelf shell sherbet shine shiny shirt
shoal shoebox shop shore shoreline shortcake shovel shower shrimp shutter sidewalk
sienna sieve sifter signal signpost silent silk silkworm silky silo silver simple
sincere sing sink sinkhole sip siskin sitar skate skating sketch skiff skiing skillet
skillful skip skirt skunk sky skylark skylight skyline skyway slate slaw sled sledding
sleek sleep sleet sleigh slicker slide slipper sloop slope sloth smart smile smock
smocking smooth smoothie snail snapper snappy snapshot snipe snooze snorkel snow
snowball snowbank snowdrift snowfield snowflake snowman snowplow snowsuit snowy snug
soapbox soapstone soar soccer social sock socket sodium sofa soft softball solar sole
solid solstice sonata songbook sonnet soothing sora sorbet sorghum sorrel souffle sound
soup sourdough souvenir soybean spacious spade spaghetti spaniel sparkle sparkly sparrow
spatula special spectrum speedy spelt sphere spinach spindle spinning spiral spirited
splash splendid sponge spool spoon sporty spotless spotlight sprig sprightly spring
springy sprinkle sprinkler sprout spruce spry spur square squash squid squirrel stable
stadium staircase stamp standby stapler star starch stardust starfish starfruit
starlight starling starry stately station statue steady steamer steel stellar stem
stencil steppe stepstone sterling stew stile stilt stitch stocking stockpot stoic stone
stony stool stopwatch stork storybook stove strainer strand strap stratus straw stream
streetcar streusel striking stripe stroll stroller strong strudel studio study stump
stunning sturdy sturgeon suave sublime subtitle subtle suburb subway succotash suede
sugar sugared sugary suitcase sultana sumac summer summery summit sun sunbaked sunbathe
sunbeam sundae sunday sundial sundress sunfish sunflower sunhat sunlit sunny sunrise
sunroom sunset sunshine super supper supple supreme sure surfing surprise sushi
suspender swale swallow swamp swan swanky sweatband sweater sweet sweetpea swift swim
swimming swing swirl switch swordfish sycamore syllabus symphony syrup tabard tabby
table tablet tabletop tack taco tadpole taffeta tag tagine tagline tahini taiga talc
talented tall tamale tamarind tame tan tanager tandem tangerine tansy tape tapestry
tapioca tapir tarn tarragon tart tartan tassel tasty tatting taupe taxi tea teacup teak
teal teapot teaspoon teddy telescope tempered tempo tempura tender tennis tent tern
terrace terrier terrific textbook thankful theater theme thermal thermos thicket thimble
thistle thorn thorough thrasher thread thrifty thriving thrush thunder thursday thyme
tiara ticket tide tidy tie tile tiller timber timeline timely timer timpani tin tinker
tinsel tiny tireless titanium toad toadstool toast toaster toffee tofu token tolerant
tongs toolbox toolshed top topaz topiary topic topical topsoil toque tortilla tortoise
tostada tote toucan touching towel tower towhee townhouse towpath tractor trail trailer
trailhead train tram tranquil travel tray treacle treetop trellis trench triangle
tributary tricycle trilby trinket tripod trivet trivia trolley trombone trophy tropical
trout trowel truck true truffle trumpet trunk trusted trusty truthful tub tuba tube
tuesday tufting tugboat tulip tulle tumbler tuna tundra tune tungsten tunic tupelo
turban tureen turkey turmeric turnip turnover turnpike turnstone turntable turquoise
turtle tutorial tutu tuxedo tweed tweezers twig twilight twill twinkling twinkly twirl
typical udon ukulele ultra umber umbrella unicycle unique united upbeat upland upright
uptown urban urchin useful usual vacation vale valiant valley valued valve van vanilla
vapor varnish vase vast vector veery vegetable velocity velour velvet veneer venerable
venue veranda verbal verbena verdant vermilion vernal verse vertex vest vestibule
viaduct vibrant vignette village vine vinegar vineyard vintage viola violet violin vireo
virtuous viscose vise visor vista visual vital vivid vocal volcano vole volt voyage
wafer waffle wagon wagtail waistcoat wakeful walkway wallaby wallet wallpaper walnut
walrus waltz wand wander wandering warbler wardrobe warehouse warm wasabi washer
waterfall watering watershed waterway watt wave wavy waxwing weasel weather weave
weaving wednesday weed week weekday weekend welcome westward wetland whale wharf wheat
wheel whimbrel whirlpool whisk whisker whistle white whitefish wholesome wick wicker
wigeon wildlife wildwood willing willow wind windbreak windchime windmill window
windsock wingspan winning winsome winter wintry wire wiry wise wish wisteria witty wok
wombat wonder wondrous wonton woodland woods woodshed woodwork woody wool woolly
workable workbench workshop worm worthy wren wrench wristband write xylophone yacht yak
yam yard yardstick yarn yarrow year yearbook yeast yellow yew yoga yogurt young youthful
yoyo zany zealous zebra zephyr zest zesty zigzag zinc zinnia zipper zippy zircon zither
ziti zucchini
""".split())

WORDS_PER_ID = 4
INSTALLATION_WORDS = 2048


def _draw(n: int, pool: Sequence[str]) -> list[str]:
    """`n` distinct words from `pool`, chosen with the operating system's random source."""
    return _RANDOM.sample(list(pool), n)


def installation_words(path: Union[str, Path]) -> tuple[str, ...]:
    """This installation's own words, chosen and saved on first use.

    A missing or damaged file (wrong count, repeats, words not in WORDS) is
    replaced. Changing the list never changes IDs already given out.
    """
    path = Path(path)
    known = set(WORDS)
    if path.exists():
        words = tuple(path.read_text().split())
        if (
            len(words) == INSTALLATION_WORDS
            and len(set(words)) == len(words)
            and set(words) <= known
        ):
            return words
    words = tuple(sorted(_draw(INSTALLATION_WORDS, WORDS)))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(words) + "\n")
    os.chmod(path, 0o600)
    return words


def make_client_id(
    taken: Callable[[str], bool] = lambda cid: False, pool: Sequence[str] = WORDS
) -> str:
    """A new four-word ID from `pool` for which `taken(id)` is False."""
    for _ in range(100):
        cid = "-".join(_draw(WORDS_PER_ID, pool))
        if not taken(cid):
            return cid
    raise RuntimeError("Could not find an unused client ID.")
