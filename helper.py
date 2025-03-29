
from enum import Enum

class ExtendedEnum(Enum):
    """
    Extended Enum class to support additional functionalities.
    """
    @classmethod
    def list(cls):
        """
        Returns a list of all enum members.
        """
        return list(cls.__members__.values())
    
    @classmethod
    def list_names(cls):
        """
        Returns a dictionary mapping enum member names to their values.
        """
        return [member.name for member in cls]

    @classmethod
    def choices(cls):
        """
        Returns a list of tuples containing enum member names and values.
        """
        return [(member.name, member.value) for member in cls]
    


